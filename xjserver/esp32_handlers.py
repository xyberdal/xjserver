import asyncio
import json
import os
import secrets
import time
import traceback
import websockets
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime
from urllib.parse import urlparse, parse_qs
# ---- Database & Omada API imports (reuse your existing modules) ----
from database import (
    get_db,
    get_pulse_mappings,
    get_duration_mappings,
    decrypt,
    hash_lookup_value,
    normalize_mac,
    update_esp32_status,
    get_site_name_by_id, safe_site_name
)

from omada_api import generate_vouchers_if_needed

# ===================== Config =====================
HOST = os.environ.get("ESP32_WS_HOST", "0.0.0.0")
PORT = int(os.environ.get("ESP32_WS_PORT", "8001"))
PATH = "/ws"

# Voucher thresholds
VOUCHER_LOW_THRESHOLD = 50
SITE_DB_PREFIX = "site_"

# ===================== In-memory state =====================
# location_name -> websocket
connections_by_location: dict[str, object] = {}

# Mirrors your discovered_esp32s usage
discovered_esp32s: dict[str, dict] = {}

# Pending voucher ACKs
pending_voucher_ack = {}
VOUCHER_RETRY_INTERVAL = 5  # seconds

# ===================== Helper: site DB =====================
import sqlite3

def get_site_db_connection(site_name):
    db_path = f"{SITE_DB_PREFIX}{safe_site_name(site_name)}.db"
    if not os.path.exists(db_path):
        print(f"⚠️ Site database {db_path} does not exist")
        return None
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def get_price_for_duration(duration_minutes):
    """Map duration to price using duration_mappings table (strict)."""
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT amount FROM duration_mappings WHERE duration = ?', (duration_minutes,))
        row = c.fetchone()
        conn.close()
        if row:
            return int(row['amount'])
        print(f"⚠️ No price mapping found for duration: {duration_minutes} minutes")
        return None
    except Exception as e:
        print(f"❌ Error getting price for duration: {e}")
        return None

def is_encrypted(code):
    # Simple check: encrypted codes are usually longer and base64-like
    return isinstance(code, str) and len(code) > 20 and all(c.isalnum() or c in '+/=' for c in code)

def get_voucher_from_database(duration_minutes, site_id):
    """Dispense oldest unused voucher from the correct site table, generating if needed."""
    try:
        price = get_price_for_duration(duration_minutes)
        if price is None:
            print(f"❌ No price mapping for {duration_minutes} minutes")
            return None

        # Try to generate vouchers, but ignore errors if Omada is offline
        try:
            generate_vouchers_if_needed(site_id, price, duration_minutes)
        except Exception as e:
            print(f"[INFO] Omada unreachable or error during voucher generation: {e}")

        site_name = get_site_name_by_id(site_id)
        if not site_name:
            print(f"❌ No site name found for site_id: {site_id}")
            return None

        conn = get_site_db_connection(site_name)
        if not conn:
            print(f"❌ Cannot connect to site DB for {site_id}")
            return None

        c = conn.cursor()
        c.execute(f"SELECT code FROM price_{price} WHERE used = 0 ORDER BY date_created ASC LIMIT 1")
        row = c.fetchone()
        if not row:
            conn.close()
            print(f"❌ No vouchers available in price_{price}")
            return None

        code = row['code']
        c.execute(f"UPDATE price_{price} SET used = 1, date_used = ? WHERE code = ?",
                  (datetime.now().isoformat(), code))
        conn.commit()
        conn.close()

        # Always decrypt if needed
        if is_encrypted(code):
            try:
                code = decrypt(code)
            except Exception as e:
                print(f"❌ Error decrypting voucher code: {e}")
                return None

        print(f"✅ Dispensed voucher from price_{price}: {code}")
        return code

    except Exception as e:
        print(f"❌ Error getting voucher from site DB: {e}")
        return None
    
def get_esp32_by_locationlog(location_name):
    """Get ESP32 device by decrypted location name (slow, but works with randomized encryption)."""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM esp32_devices")
    for row in c.fetchall():
        try:
            if decrypt(row["location_name"]) == location_name:
                conn.close()
                return row
        except Exception:
            continue
    conn.close()
    return None

# ===================== Serialization helpers =====================

async def send_json(ws, payload: dict):
    await ws.send(json.dumps(payload))

async def send_to_location(location: str, payload: dict):
    """Convenience: send to a connected location if present."""
    ws = connections_by_location.get(location)
    if ws:
        try:
            await send_json(ws, payload)
        except Exception as e:
            print(f"❌ Send failed to {location}: {e}")

# ===================== Voucher retry worker =====================

async def voucher_retry_worker():
    """Periodically re-send voucher to a location until acknowledged."""
    while True:
        try:
            now = time.time()
            to_retry = []
            for location, info in list(pending_voucher_ack.items()):
                if now - info["timestamp"] > VOUCHER_RETRY_INTERVAL:
                    to_retry.append((location, info))

            for location, info in to_retry:
                await send_to_location(location, {
                    "action": "voucher_generated",
                    "success": True,
                    "voucher_code": info["voucher_code"],
                    "duration": info.get("duration", 0),
                    "amount": info.get("amount", 0)
                })
                info["timestamp"] = now
                info["retries"] += 1
                print(f"🔄 Retrying voucher to {location}: {info['voucher_code']} (retry {info['retries']})")

        except Exception as e:
            print(f"❌ voucher_retry_worker error: {e}")
        await asyncio.sleep(1)

# ===================== Connection auth =====================

def verify_mac_signature(mac, signature_b64, publickey_pem):
    """
    Verifies that the signature is valid for the given MAC address and public key.
    Returns True if valid, False otherwise.
    """
    try:
        pubkey = serialization.load_pem_public_key(publickey_pem.encode())
        signature = base64.b64decode(signature_b64)
        pubkey.verify(
            signature,
            mac.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print("MAC signature verification failed:", e)
        return False


async def authenticate_connection(query: dict):
    """
    Returns (ok, reason) and normalized connection context:
    {
      device_type, location_name, mac_address
    }
    """
    device_type = query.get("device_type", "coinslot")
    if device_type is not None:
        device_type = str(device_type).strip()
    else:
        device_type = "coinslot"
    
    api_secret = query.get("api_secret", None)
    if api_secret is not None:
        api_secret = str(api_secret).strip()
    
    token = query.get("token", None)
    if token is not None:
        token = str(token).strip()
    
    mac_address = query.get("mac_address", None)
    if mac_address is not None:
        mac_address = str(mac_address).strip()
    
    if not mac_address or (not token and not api_secret):
        return (False, "Missing mac_address and token/api_secret", None, None, None, None)

    conn = get_db()
    c = conn.cursor()

    try:
        print("=== DEBUG: All esp32_devices in DB ===")
        c.execute('SELECT location_name, api_secret, mac_address, ws_token FROM esp32_devices')
        all_devices = c.fetchall()
        for d in all_devices:
            print({
                "location_name": d["location_name"],
                "api_secret": d["api_secret"],
                "mac_address": d["mac_address"],
                "ws_token": d["ws_token"]
            })
        print("=== END DEBUG ===")

        incoming_mac_hash = hash_lookup_value(normalize_mac(mac_address))

        # Try API secret authentication
        # ...existing code...
        if api_secret:
            c.execute(
                '''SELECT * FROM esp32_devices WHERE mac_address = ?''',
                (incoming_mac_hash,)
            )
            device = c.fetchone()
            if device and device["publickey"]:
                # Use the MAC address as the message
                mac_for_verification = mac_address  # Use the original MAC, not hashed
                if verify_mac_signature(mac_for_verification, api_secret, device["publickey"]):
                    # Valid license, erase ws_token and publickey (one-time use)
                    c.execute('UPDATE esp32_devices SET ws_token = "", publickey = "" WHERE mac_address = ?', (incoming_mac_hash,))
                    conn.commit()
                    conn.close()
                    print("  --> MAC signature valid, ws_token and publickey erased")
                    return (True, "", device_type, device["location_name"], mac_address, None, device["site_id"])
                else:
                    conn.close()
                    print("  --> MAC signature invalid")
                    return (False, "Invalid license signature", None, None, None, None, None)
            else:
                conn.close()
                print("  --> No publickey found for device")
                return (False, "No publickey for device", None, None, None, None, None)
        
        elif token:
            print(f"Token from ESP32 (for query): '{token}' (repr: {repr(token)})")
            # Print all tokens in the DB for comparison
            c.execute('SELECT ws_token, mac_address FROM esp32_devices')
            all_tokens = c.fetchall()
            for d in all_tokens:
                print(f"DB ws_token: '{d['ws_token']}' (repr: {repr(d['ws_token'])}), mac_address: {d['mac_address']}")
            # Now do the actual query
            c.execute(
                '''SELECT * FROM esp32_devices WHERE ws_token = ?''', (token.strip(),)
            )
            device = c.fetchone()
            print(f"Query result for token: {device}")
            if device:
                print(f"  DB mac_address: {device['mac_address']}")
                print(f"  Incoming mac_address (hashed): {incoming_mac_hash}")
            else:
                print("  No device found for given token")
            if not device or device['mac_address'] != incoming_mac_hash:
                conn.close()
                print("  --> No match foundTOKEN")
                return (False, "Invalid token for device", None, None, None, None)
            # Return api_secret to caller, also invalidate token
            # Fetch api_secret from DB
            api_secret_value = device["api_secret"]
            if not api_secret_value or api_secret_value.strip() == "":
                # Treat as unadopted: no api_secret set
                conn.close()
                print("  --> No api_secret in DB, treating as unadopted")
                return (False, "Device not adopted (no api_secret set)", None, None, None, None, None)
            
            conn.close()
            print("  --> MATCH FOUND, returning existing api_secret")
            return (True, "", device_type, device["location_name"], mac_address, api_secret_value, device["site_id"])
    except Exception as e:
        conn.close()
        return (False, f"Auth DB error: {e}", None, None, None, None)

# ===================== Message handlers =====================

async def handle_request_mappings(ws):
    """Send pulse and duration mappings to ESP32."""
    try:
        pulse_mappings = get_pulse_mappings()
        pulse_data = [{"pulse_count": m["pulse_count"], "amount": m["amount"]} for m in pulse_mappings]

        duration_mappings = get_duration_mappings()
        duration_data = [{"amount": m["amount"], "duration": m["duration"]} for m in duration_mappings]

        await send_json(ws, {
            "action": "mappings_response",
            "success": True,
            "pulse_map": {m["pulse_count"]: m["amount"] for m in pulse_mappings},
            "duration_map": {m["amount"]: m["duration"] for m in duration_mappings}
        })
        print(f"📋 Sent mappings: {len(pulse_mappings)} pulse, {len(duration_mappings)} duration")
    
    except Exception as e:
        await send_json(ws, {"action": "mappings_response", "success": False, "error": str(e)})
        print(f"❌ Error sending mappings: {e}")

async def handle_coin_payment_update(ws, data: dict, location: str):
    try:
        amount = data.get("amount", 0)
        duration = data.get("duration", 0)
        pulse_count = data.get("pulse_count", 0)

        conn = get_db()
        c = conn.cursor()
        c.execute(
            '''INSERT INTO coin_logs (site_id, device_type, location_name, amount, inserted_at)
               VALUES (?, ?, ?, ?, ?)''',
            ('esp32', 'coinslot', location, amount, datetime.now().isoformat())
        )
        conn.commit()
        conn.close()

        await send_json(ws, {"action": "payment_update_ack", "status": "success",
                             "message": f"Payment logged: ₱{amount} ({duration} min)"})
        print(f"💰 {location} payment: ₱{amount}, {duration} min, {pulse_count} pulses")

    except Exception as e:
        await send_json(ws, {"action": "payment_update_ack", "status": "error", "error": str(e)})
        print(f"❌ Error handling payment update: {e}")

async def handle_ping(ws, location: str):
    await send_json(ws, {"action": "pong", "timestamp": time.time(), "server_time": datetime.now().isoformat()})
    if location in discovered_esp32s:
        discovered_esp32s[location]["last_seen"] = datetime.now().isoformat()
    print(f"🏓 Ping/Pong with {location}")

async def handle_request_voucher(ws, data: dict, location: str):
    try: 
        duration = data.get("duration")
        amount = data.get("amount")
        location = data.get("location", location)  # Use provided location or fallback
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute("""
                INSERT INTO coin_logs (location_name, amount, duration)
                VALUES (?, ?, ?)
            """, (
                location,
                amount if amount is not None else 0,
                duration if duration is not None else 0
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[ERROR] Failed to log coin insert: {e}")

        # Now handle missing data after logging attempt
        if duration is None and amount is None:
            await send_json(ws, {"action": "voucher_generated", "success": False, "error": "Missing duration and amount"})
            return

        # Lookup device info by location name
        print(f"[DEBUG] Looking up device by location: {location}")
        device_row = get_esp32_by_locationlog(location)
        print(f"[DEBUG] device_row: {device_row}")
        if not device_row:
            print(f"[DEBUG] No device found for location: {location}")
            await send_json(ws, {"action": "voucher_generated", "success": False, "error": "Unknown device location"})
            return
        site_id = device_row["site_id"]
        print(f"[DEBUG] Found site_id: {site_id} for location: {location}")
        
        # Get site name from site_id
        site_name = get_site_name_by_id(site_id)
        if not site_name:
            print(f"[DEBUG] No site_name found for site_id: {site_id}")
            await send_json(ws, {"action": "voucher_generated", "success": False, "error": "No site_name for site_id"})
            return

        # Get price for the requested duration
        duration_mappings = get_duration_mappings()
        price = None
        for mapping in duration_mappings:
            if str(mapping.get("duration")) == str(duration):
                price = mapping.get("amount")
                break
        
        if price is None:
            await send_json(ws, {
                "action": "voucher_generated",
                "success": False,
                "error": f"No price mapping for {duration} min"
            })
            return

        # Generate vouchers if needed and get a voucher code
        generate_vouchers_if_needed(site_id, price, duration)
        conn = get_site_db_connection(site_name)
        if not conn:
            await send_json(ws, {"action": "voucher_generated", "success": False, "error": "Cannot connect to site DB"})
            return

        c = conn.cursor()
        c.execute(f"SELECT code FROM price_{price} WHERE used = 0 ORDER BY date_created ASC LIMIT 1")
        row = c.fetchone()
        if not row:
            conn.close()
            await send_json(ws, {"action": "voucher_generated", "success": False, "error": "No vouchers available"})
            return

        code = row['code']
        c.execute(f"UPDATE price_{price} SET used = 1, date_used = ? WHERE code = ?", (datetime.now().isoformat(), code))
        conn.commit()
        conn.close()

        # Send voucher to ESP32
        await send_to_location(location, {
            "action": "voucher_generated",
            "success": True,
            "voucher_code": code,
            "duration": duration,
            "price": price  # Optionally send price if you want
        })
        # Track pending ack
        pending_voucher_ack[location] = {
            "voucher_code": code,
            "timestamp": time.time(),
            "retries": 0,
            "duration": duration,
            "price": price
        }
        print(f"🎫 Sent voucher to {location}: {code} ({duration} min, ₱{price}) - awaiting ack")

    except Exception as e:
        await send_json(ws, {"action": "voucher_generated", "success": False, "error": str(e)})


async def handle_voucher_ack(location: str, data: dict):
    """Optional: if ESP32 sends ack, stop retries and log usage."""
    code = data.get("voucher_code")
    info = pending_voucher_ack.get(location)
    print(f"[DEBUG] handle_voucher_ack called for location: {location}")
    print(f"[DEBUG] Received voucher_code: {code}")
    print(f"[DEBUG] Pending info: {info}")
    if info:
        print(f"[DEBUG] Comparing received code '{code}' with expected '{info.get('voucher_code')}'")
    if info and info.get("voucher_code") == code:
        # --- Log voucher usage in main DB ---
        try:
            device_row = get_esp32_by_locationlog(location)
            conn_main = get_db()
            c_main = conn_main.cursor()
            c_main.execute("""
                INSERT INTO voucher_usage_logs (voucher_code, device_type, amount, location_name, used_at)
                VALUES (?, ?, ?, ?, ?)
            """, (
                code,
                device_row["device_type"] if device_row and "device_type" in device_row else "coinslot",
                info.get("price", 0),
                location,
                datetime.now().isoformat()
            ))
            conn_main.commit()
            conn_main.close()
            print(f"✅ Logged voucher usage: {code} at {location}")
        except Exception as e:
            print(f"❌ Failed to log voucher usage: {e}")
        # --- End log ---

        del pending_voucher_ack[location]
        print(f"✅ Voucher ACK received from {location}: {code}")
    else:
        print(f"[DEBUG] Voucher ACK did not match or no pending info for {location}")


# ===================== Main connection handler =====================
async def ws_handler(ws):
    print("New WebSocket connection received")
    print("WS OBJECT:", ws)
    # Optionally, print the remote address if available
    if hasattr(ws, "remote_address"):
        print("Remote address:", ws.remote_address)
    
    try:
        raw = await ws.recv()
        print("First message from client:", raw)
        try:
            query = json.loads(raw)
        except Exception as e:
            print("Error parsing first message as JSON:", e)
            await ws.close()
            return
    except Exception as e:
        print("Error receiving first message:", e)
        await ws.close()
        return

    # Authenticate connection using the parsed query dict
    ok, reason, device_type, location_name, mac_address, api_secret_to_return, site_id = await authenticate_connection(query)
    if not ok:
        print(f"❌ Connection rejected: {reason}")
        try:
            await send_json(ws, {"action": "connected", "success": False, "error": reason})
        except Exception:
            pass
        await ws.close(code=1008, reason=reason)
        return

    # Register connection, but check for duplicate first
    mac_hash = hash_lookup_value(normalize_mac(mac_address))
    decrypted_location = decrypt(location_name)
    
    
    # Only add to connections_by_location if authenticated by API secret (not just token)
    if not api_secret_to_return:
        if decrypted_location in connections_by_location:
            print(f"⚠️ Duplicate connection attempt for {decrypted_location}. Closing both connections.")
            old_ws = connections_by_location[decrypted_location]
            try:
                await old_ws.close(code=4000, reason="Duplicate connection detected")
            except Exception as e:
                print(f"Error closing old connection: {e}")
            try:
                await ws.close(code=4001, reason="Duplicate connection detected (both closed)")
            except Exception as e:
                print(f"Error closing new connection: {e}")
            return  # Do not register the new connection
    
        connections_by_location[decrypted_location] = ws
        print_online_connections()
    
        if decrypted_location not in discovered_esp32s:
            discovered_esp32s[decrypted_location] = {}
        discovered_esp32s[decrypted_location]["is_online"] = True
        update_esp32_status(mac_hash, True, ip=ws.remote_address[0])
    
    # ...rest of your code...e_esp32_status(mac_hash, True, ip=ws.remote_address[0])

    try:
        # If adopted with token, deliver api_secret once
        if api_secret_to_return:
            await send_json(ws, {"action": "api_secret", "api_secret": api_secret_to_return, "site_id": site_id})
            print(f"✅ Sent api_secret to newly adopted ESP32: {location_name}")

        await send_json(ws, {
            "action": "connected",
            "success": True,
            "msg": f"Connected as {device_type} at {location_name}"
        })
        print(f"✅ ESP32 connected: {location_name}")

        # Receive loop
        async for raw in ws:
            try:
                data = json.loads(raw)
                action = (data.get("action") or "").strip().lower()

                if action == "request_mappings":
                    await handle_request_mappings(ws)

                elif action == "coin_payment_update":
                    await handle_coin_payment_update(ws, data, decrypted_location)

                elif action == "ping":
                    await handle_ping(ws, decrypted_location)

                elif action == "request_voucher":
                    await handle_request_voucher(ws, data, decrypted_location)

                elif action == "voucher_ack":
                    await handle_voucher_ack(decrypted_location, data)

                else:
                    await send_json(ws, {"action": "error", "error": f"Unknown action: {action}"})

            except json.JSONDecodeError:
                await send_json(ws, {"action": "error", "error": "Invalid JSON"})
            except Exception as e:
                print(f"❌ Handler error: {e}\n{traceback.format_exc()}")
                await send_json(ws, {"action": "error", "error": str(e)})

    except websockets.ConnectionClosed:
        pass
    finally:
        # Cleanup on disconnect
        if connections_by_location.get(decrypted_location) is ws:
            del connections_by_location[decrypted_location]
        if decrypted_location in discovered_esp32s:
            discovered_esp32s[decrypted_location]["is_online"] = False
        if decrypted_location in pending_voucher_ack:
            del pending_voucher_ack[decrypted_location]
        print(f"❌ ESP32 disconnected: {decrypted_location}")
        update_esp32_status(mac_hash, False)
        print_online_connections()

def print_online_connections():
    print("=== Online ESP32 Connections ===")
    for location, ws in connections_by_location.items():
        print(f"Location: {location} | WebSocket: {ws}")
    print("=== END ONLINE LIST ===")


async def main():
    asyncio.create_task(voucher_retry_worker())
    async with websockets.serve(ws_handler, HOST, PORT):
        print(f"🚀 WebSocket server running at ws://{HOST}:{PORT}{PATH}")
        await asyncio.Future()  # run forever

# ===================== Entrypoint =====================

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 Shutting down ESP32 WS server…")
    except Exception as e:
        print("\n💥 ESP32 WS server crashed!")
        print(f"Reason: {e}")
        import traceback
        traceback.print_exc()