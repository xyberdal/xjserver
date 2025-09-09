import socket
import json
import sqlite3
import os
import logging

from datetime import datetime
from cryptography.fernet import Fernet

from database import hash_lookup_value, normalize_mac

logging.basicConfig(
    filename='xjserver.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s'
)

UDP_PORT = 4210
DATABASE = 'xjserver.db'

discovered_esp32s = {}

FERNET_KEY = os.environ.get('XJSERVER_ENCRYPT_KEY')
if not FERNET_KEY:
    raise RuntimeError("XJSERVER_ENCRYPT_KEY not set in environment (systemd)")

if isinstance(FERNET_KEY, str):
    cipher_suite = Fernet(FERNET_KEY.encode())
else:
    cipher_suite = Fernet(FERNET_KEY)

def encrypt(val):
    if val is None:
        return None
    return cipher_suite.encrypt(str(val).encode()).decode()

def decrypt(val):
    if val is None:
        return None
    return cipher_suite.decrypt(val.encode()).decode()

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def get_known_devices():
    try:
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT device_type, location_name, mac_address, api_secret FROM esp32_devices")
        devices = {}
        for row in c.fetchall():
            device_type = decrypt(row[0])
            location_name = decrypt(row[1])
            mac_address_hash = row[2]  # Already hashed, do not decrypt!
            api_secret = decrypt(row[3])
            devices[location_name] = {
                'device_type': device_type,
                'location_name': location_name,
                'mac_address_hash': mac_address_hash,
                'api_secret': api_secret
            }
        conn.close()
        return devices
    except Exception as e:
        logging.error(f"Error getting known devices: {e}")
        return {}

def validate_esp32_payload(payload, addr):
    try:
        device_type = payload.get("device_type")
        location_name = payload.get("name")
        mac_address = payload.get("mac_address")
        version = payload.get("version", "unknown")
        uptime = payload.get("uptime", 0)
        if not device_type:
            print(f"UDP: Invalid payload from {addr[0]} - missing device_type")
            logging.error(f"UDP: Invalid payload from {addr[0]} - missing device_type")
            return None
        return {
            'device_type': device_type,
            'location_name': location_name,
            'mac_address': mac_address,
            'version': version,
            'uptime': uptime,
            'ip': addr[0],
            'last_seen': datetime.now().isoformat()
        }
    except Exception as e:
        print(f"UDP: Error validating payload from {addr[0]}: {e}")
        logging.error(f"UDP: Error validating payload from {addr[0]}: {e}")
        return None

def get_ws_url_for_device(device_info):
    ws_url = (f"ws://{get_local_ip()}:8001/ws")
    return ws_url

def handle_esp32_discovery(device_info, addr, sock):
    device_type = device_info['device_type']
    location_name = device_info['location_name']
    mac_address = device_info['mac_address']
    ip = device_info['ip']
    key = location_name if location_name else ip
    discovered_esp32s[key] = device_info
    print(f"UDP: Discovered {device_type} at {ip}")
    logging.info(f"UDP: Discovered {device_type} at {ip}")
    if location_name:
        print(f"  - Location: {location_name}")
    if mac_address:
        print(f"  - MAC: {mac_address}")
    known_devices = get_known_devices()
    if location_name and location_name in known_devices:
        device_config = known_devices[location_name]
        if mac_address:
            incoming_mac_hash = hash_lookup_value(normalize_mac(mac_address))
            if device_config['mac_address_hash'] != incoming_mac_hash:
                print(f"UDP: MAC mismatch for {location_name} - expected hash {device_config['mac_address_hash']}, got hash {incoming_mac_hash}")
                logging.error(f"UDP: MAC mismatch for {location_name} - expected hash {device_config['mac_address_hash']}, got hash {incoming_mac_hash}")
                response = json.dumps({"error": "MAC_MISMATCH"}).encode()
                sock.sendto(response, addr)
                return
        ws_url = get_ws_url_for_device(device_config)
        print(f"{ws_url}")
        response = json.dumps({
            "status": "adopted",
            "ws_url": ws_url,
            "server_ip": get_local_ip(),
            "server_time": datetime.now().isoformat()
        }).encode()
        sock.sendto(response, addr)
        print(f"UDP: Sent WebSocket URL to adopted device '{location_name}' at {ip}")
    else:
        if location_name:
            print(f"UDP: Unknown location '{location_name}' from {ip}, needs admin adoption")
        else:
            print(f"UDP: Unadopted ESP32 from {ip}, needs admin adoption")
        response = json.dumps({
            "status": "unadopted",
            "cmd": "mount_me",
            "message": "Device needs to be adopted by admin",
            "server_ip": get_local_ip(),
            "admin_url": f"http://{get_local_ip()}:8000/admin"
        }).encode()
        sock.sendto(response, addr)
        print(f"UDP: Sent adoption (mount_me) response to {addr[0]}:{addr[1]}")

def udp_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(('', UDP_PORT))
        print(f"🎧 Listening for ESP32 UDP broadcasts on port {UDP_PORT}...")
        print(f"🖥️  Server IP: {get_local_ip()}")
        while True:
            try:
                data, addr = sock.recvfrom(1024)
                print(f"UDP listener loop: received data from {addr}")
                try:
                    payload = json.loads(data.decode())
                except json.JSONDecodeError:
                    print(f"UDP: Invalid JSON from {addr[0]}")
                    continue
                device_info = validate_esp32_payload(payload, addr)
                if not device_info:
                    continue
                device_type = device_info['device_type']
                if device_type in ("esp32", "coinslot"):
                    handle_esp32_discovery(device_info, addr, sock)
                # Add more device types if needed
            except Exception as e:
                print(f"UDP: Error processing packet: {e}")
                continue
    except Exception as e:
        print(f"UDP: Fatal error in listener: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    print("🔧 XJServer ESP32 UDP Discovery Service")
    print("======================================")
    udp_listener()
