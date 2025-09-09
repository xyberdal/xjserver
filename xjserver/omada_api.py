import os
import sqlite3
import requests
import urllib3
import time
import subprocess
import re
import platform
import psutil
import ipaddress
import socket
import random
import string
from urllib.parse import urlparse
from cryptography.fernet import Fernet
from scapy.all import ARP, Ether, srp

from database import decrypt, normalize_mac, get_db, add_site, create_site_database, get_site_name_by_id, store_voucher_codes
# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DATABASE = 'xjserver.db'
SITE_DB_PREFIX = 'site_'
FERNET_KEY = os.environ.get('XJSERVER_ENCRYPT_KEY')
if not FERNET_KEY:
    raise RuntimeError("XJSERVER_ENCRYPT_KEY not set in environment")
fernet = Fernet(FERNET_KEY.encode() if isinstance(FERNET_KEY, str) else FERNET_KEY)


def ping_host(ip, timeout=1):
    system = platform.system().lower()
    try:
        if system == "windows":
            result = subprocess.run(["ping", "-n", "1", "-w", str(timeout * 1000), ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            result = subprocess.run(["ping", "-c", "1", "-W", str(timeout), ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception as e:
        print(f"Ping error for {ip}: {e}")
        return False

def periodic_controller_ip_scan():
    def scan():
        global OMADA_INTERFACE_ACCESS_ADDRESS
        params = get_latest_api_voucher_params()
        if not params:
            print("[SCAN] No Omada config found.")
            return False  # Not found

        controller_ip = params.get("controller_ip")
        controller_port = params.get("controller_port")
        controller_mac = params.get("controller_mac")
        # 1. Try last known controller_ip up to 10 times
        if controller_ip:
            print(f"[SCAN] Trying last known controller IP: {controller_ip}")
            for attempt in range(5):
                if ping_host(controller_ip):
                    OMADA_INTERFACE_ACCESS_ADDRESS = f"https://{controller_ip}:{controller_port}"
                    print(f"[SCAN] Controller reachable at {OMADA_INTERFACE_ACCESS_ADDRESS}")
                    from admin_routes import check_all_voucher_stocks_on_startup
                    check_all_voucher_stocks_on_startup()
                    return True  # Found
                print(f"[SCAN] Ping attempt {attempt+1}/10 failed, retrying in 3s...")
                time.sleep(3)
        # 2. If not found, scan subnet (ARP)
        subnet = get_local_subnet()
        if not subnet:
            print("[SCAN] No subnet detected.")
            return False
        target_ip = subnet
        oc_mac = controller_mac.upper()
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=2, verbose=False)[0]
        for sent, received in result:
            if received.hwsrc.upper() == oc_mac:
                controller_ip = received.psrc
                conn = get_db()
                c = conn.cursor()
                c.execute("UPDATE api_voucher_params SET controller_ip = ? WHERE id = (SELECT id FROM api_voucher_params ORDER BY id DESC LIMIT 1)", (controller_ip,))
                conn.commit()
                conn.close()
                OMADA_INTERFACE_ACCESS_ADDRESS = f"https://{controller_ip}:{controller_port}"
                print(f"[SCAN] Controller found by ARP scan at {controller_ip}")
                from admin_routes import check_all_voucher_stocks_on_startup
                check_all_voucher_stocks_on_startup()
                return True  # Found
        print("[SCAN] Controller not found in subnet after full scan.")
        return False  # Not found

    return scan()  # <-- This line actually runs the scan when you call periodic_controller_ip_scan()
    
def generate_code(length, fmt):
    """Generate voucher code based on format"""
    if fmt == "numeric":
        chars = string.digits
    elif fmt == "alpha":
        chars = string.ascii_uppercase
    else:
        chars = string.ascii_uppercase + string.digits
    return ''.join(random.choices(chars, k=length))

def safe_site_name(site_name):
    return re.sub(r'[^A-Za-z0-9_\-]', '_', site_name.strip())

def get_local_subnet():
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                ip = addr.address
                netmask = addr.netmask
                if ip and netmask:
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    return str(network)
    return None

def find_controller_ip_by_mac(mac_address):
    """
    Auto-detect the local subnet, ping all IPs in the LAN to populate the ARP table,
    then parse the ARP table for the given MAC address (LAN only).
    Prints the ARP table for debugging.
    Returns the IP as a string, or None if not found.
    """
    import subprocess
    import re
    import platform
    import os

    # Step 1: Get local IP and subnet
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception as e:
        print(f"Could not determine local IP: {e}")
        return None

    subnet = get_local_subnet()
    print(f"Detected subnet: {subnet}")

    # Step 2: Ping all IPs in the subnet to populate ARP table
    net = ipaddress.ip_network(subnet, strict=False)
    system = platform.system().lower()
    print(f"Pinging all IPs in {subnet} to populate ARP table...")
    for ip in net.hosts():
        ip_str = str(ip)
        try:
            if system == "windows":
                subprocess.run(["ping", "-n", "1", "-w", "100", ip_str], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                subprocess.run(["ping", "-c", "1", "-W", "1", ip_str], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            print(f"Ping error for {ip_str}: {e}")
    # Step 3: Parse ARP table for the MAC address (LAN only)
    try:
        if system == "windows":
            output = subprocess.check_output("arp -a", shell=True, encoding="utf-8")
            print("=== ARP TABLE (Windows) ===")
            print(output)
            print("===========================")
            for line in output.splitlines():
                # Extract IP and MAC from each line
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)[^\w:]+((?:[0-9a-f]{2}[-:]){5}[0-9a-f]{2})', line, re.I)
                if match:
                    ip = match.group(1)
                    mac_in_arp = normalize_mac(match.group(2))
                    if ipaddress.ip_address(ip) in net and mac_in_arp == mac_address:
                        print(f"Found IP {ip} for MAC {mac_in_arp}")
                        return ip
        else:
            output = subprocess.check_output("arp -a", shell=True, encoding="utf-8")
            print("=== ARP TABLE (Linux/Unix) ===")
            print(output)
            print("==============================")
            for line in output.splitlines():
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)[^\w:]+((?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2})', line, re.I)
                if match:
                    ip = match.group(1)
                    mac_in_arp = normalize_mac(match.group(2))
                    if ipaddress.ip_address(ip) in net and mac_in_arp == mac_address:
                        print(f"Found IP {ip} for MAC {mac_in_arp}")
                        return ip
    except Exception as e:
        print(f"Error in find_controller_ip_by_mac: {e}")
    print(f"MAC address {mac_address} not found in ARP table.")
    return None

def get_latest_api_voucher_params():
    """Get the latest API voucher parameters from database"""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM api_voucher_params ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    params = dict(row)
    # Decrypt client_id and client_secret
    if params.get("client_id"):
        params["client_id"] = decrypt(params["client_id"])
    if params.get("client_secret"):
        params["client_secret"] = decrypt(params["client_secret"])
    if params.get("omada_id"):
        params["omada_id"] = decrypt(params["omada_id"])
    if params.get("controller_mac"):
        params["controller_mac"] = decrypt(params["controller_mac"])
    if params.get("controller_port"):
        params["controller_port"] = decrypt(params["controller_port"])
    return params


def ensure_site_database(site_id, site_name):
    """Check if the site DB exists; if not, create it and add the site to the main DB."""
    db_path = f"{SITE_DB_PREFIX}{safe_site_name(site_name)}.db"
    if not os.path.exists(db_path):
        print(f"Creating site DB for {site_name}...")
        add_site(site_id, site_name)  # This will also call create_site_database(site_id)
    else:
        print(f"Site DB for {site_name} already exists.")

def authenticate_omada_controller(max_retries=5, retry_delay=8):
    """Authenticate with Omada Controller using Open API credentials, with retries."""
    glovar = get_latest_api_voucher_params()
    if not glovar:
        print("No Omada API configuration found in database.")
        return None, None
    
    OMADA_CLIENT_ID = glovar.get('client_id')
    OMADA_CLIENT_SECRET = glovar.get('client_secret')
    OMADA_ID = glovar.get('omada_id')
    IP = glovar.get('controller_ip')
    PORT = glovar.get('controller_port')
    OMADA_INTERFACE_ACCESS_ADDRESS = f"https://{IP}:{PORT}" if IP and PORT else None
    
    for attempt in range(1, max_retries + 1):
        try:
            if OMADA_INTERFACE_ACCESS_ADDRESS:
                ip = urlparse(OMADA_INTERFACE_ACCESS_ADDRESS).hostname
                if not ping_host(ip):
                    print(f"[FAIL] Controller IP {ip} is not reachable (ping failed).")
                    # continue to retry
                else:
                    print(f"[OK] Controller IP {ip} is reachable (ping successful).")

            if not OMADA_CLIENT_ID or not OMADA_CLIENT_SECRET:
                print("ERROR: No OMADA_CLIENT_ID or OMADA_CLIENT_SECRET found in environment")
                return None, None

            # Create session
            session = requests.Session()
            session.verify = False

            # Official Omada Open API endpoint
            token_endpoint = f"{OMADA_INTERFACE_ACCESS_ADDRESS}/openapi/authorize/token"
            params = {'grant_type': 'client_credentials'}
            body_data = {
                'omadacId': OMADA_ID,
                'client_id': OMADA_CLIENT_ID,
                'client_secret': OMADA_CLIENT_SECRET
            }
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }

            print(f"DEBUG: Using client credentials mode")
            response = session.post(token_endpoint,
                                   params=params,
                                   json=body_data,
                                   headers=headers,
                                   timeout=10)
            if response.status_code == 200:
                result = response.json()
                print(f"SUCCESS! Authenticated with Omada Open API")

                if result.get('errorCode') == 0:
                    token_data = result.get('result', {})
                    access_token = token_data.get('accessToken')
                    token_type = token_data.get('tokenType', 'bearer')
                    expires_in = token_data.get('expiresIn')

                    if access_token:
                        session.headers.update({'Authorization': f'AccessToken={access_token}'})
                        return session, access_token
                    else:
                        print("[FAIL] No accessToken in successful response")
                else:
                    error_code = result.get('errorCode')
                    error_msg = result.get('msg', 'Unknown error')
                    print(f"[FAIL] API Error {error_code}: {error_msg}")

            elif response.status_code == 404:
                print("[FAIL] 404 Not Found - Check if Open API is enabled")
                print("[INFO] Go to Settings > Platform Integration > Open API")

            elif response.status_code == 401:
                print("[FAIL] 401 Unauthorized - Invalid credentials")

            else:
                print(f"[FAIL] HTTP {response.status_code}: {response.text}")

        except Exception as e:
            print(f"[FAIL] Open API authentication error: {e}")

        # Delay before next attempt, only if not successful and not last attempt
        if attempt < max_retries:
            print(f"Retrying in {retry_delay} seconds...")
            time.sleep(retry_delay)

    print("[FAIL] Could not authenticate with Omada Controller after multiple attempts.")
    return None, None

def generate_vouchers_if_needed(site_id, price, duration):
    """If stock low, call Omada API to generate vouchers (and store them inside the API function)."""
    try:
        current_stock = check_voucher_stock(site_id, price)
        print(f"📊 Stock ₱{price} ({duration} min): {current_stock} vouchers")
        if current_stock >= 50:
            print(f"✅ Stock sufficient for ₱{price}")
            return True

        print(f"🔄 Low stock detected ({current_stock} < 50). Generating…")
        voucher_params = get_latest_api_voucher_params()
        
        voucher_params["unit_price"] = price
        voucher_params["duration"] = duration

        # This function handles both voucher creation
        success, codes = create_omada_vouchers_via_api(site_id, voucher_params)
        if not (success and codes):
            print("❌ Failed to generate vouchers via Omada API")
            return False

        print(f"✅ Generated and stored {len(codes)} voucher codes for ₱{price}")
        return True

    except Exception as e:
        print(f"❌ Error in voucher generation check: {e}")
        return False

def check_voucher_stock(site_id, price):
    """
    Returns the count of unused vouchers for a given site and price.
    """
    try:
        site_name = get_site_name_by_id(site_id)
        if not site_name:
            print(f"⚠️ Site name for site_id '{site_id}' not found.")
            return 0
        db_path = f"{SITE_DB_PREFIX}{safe_site_name(site_name)}.db"
        if not os.path.exists(db_path):
            print(f"⚠️ Site database {db_path} does not exist")
            return 0
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute(f"SELECT COUNT(*) FROM price_{price} WHERE used = 0")
        count = c.fetchone()[0]
        conn.close()
        return count
    except Exception as e:
        print(f"❌ Error checking voucher stock: {e}")
        return 0

def random_voucher_group_name(length=8):
    return "VG_" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def create_omada_vouchers_via_api(site_id, voucher_params, retry=False):
    """
    Fully self-contained Omada voucher creation workflow.
    All Omada API logic is inlined here to ensure a single session/token is used.
    """
    voucher_params2 = get_latest_api_voucher_params()
    if not voucher_params2:
        print("No Omada API configuration found in database.")
        return None, None

    OMADA_CLIENT_ID = voucher_params2.get('client_id')
    OMADA_CLIENT_SECRET = voucher_params2.get('client_secret')
    OMADA_ID = voucher_params2.get('omada_id')
    IP = voucher_params2.get('controller_ip')
    PORT = voucher_params2.get('controller_port')
    OMADA_INTERFACE_ACCESS_ADDRESS = f"https://{IP}:{PORT}" if IP and PORT else None

    if OMADA_INTERFACE_ACCESS_ADDRESS is None:
        print("❌ Omada controller not reachable. Aborting voucher stock check.")
        return  # Stop further execution
    # Step 1: Authenticate once
    session, token = authenticate_omada_controller()
    if not session:
        print("[FAIL] Omada Controller authentication failed. Aborting voucher generation.")
        return False, []

    controller_url = OMADA_INTERFACE_ACCESS_ADDRESS

    # Step 2: Get list of sites
    try:
        sites_url = f"{controller_url}/openapi/v1/{OMADA_ID}/sites"
        params = {'pageSize': 10, 'page': 1}
        response = session.get(sites_url, params=params, timeout=10)
        if response.status_code != 200:
            print(f"[FAIL] Sites request failed: {response.status_code}")
            return False, []
        result = response.json()
        if result.get('errorCode') != 0:
            print(f"[FAIL] Sites API error: {result.get('msg')}")
            return False, []
        sites = result.get('result', {}).get('data', [])
    except Exception as e:
        print(f"[FAIL] Error getting sites: {e}")
        return False, []

    # Step 3: Find the target site
    target_site = None
    for site in sites:
        site_id_from_api = site.get('siteId')
        site_name_from_api = site.get('name')
        try:
            add_site(site_id_from_api, site_name_from_api)
            ensure_site_database(site_id_from_api, site_name_from_api)
        except Exception as e:
            print(f"⚠️ Error processing site {site_id_from_api}: {e}")
            break
        if site.get('siteId') == site_id:
            target_site = site
            break
    if not target_site:
        print(f"Site {site_id} not found in Omada Controller")
        return False, []
    
    omada_site_id = target_site.get('siteId')
    # ...existing code...
    # Step 4: Get voucher group amount limit from controller
    try:
        limit_url = f"{controller_url}/openapi/v1/{OMADA_ID}/sites/{omada_site_id}/hotspot/voucher-groups/config-limit"
        response = session.get(limit_url, timeout=10)
        if response.status_code == 200:
            result = response.json()
            if result.get('errorCode') == 0:
                limits = result.get('result', [])
                if limits and "amountLimit" in limits[0]:
                    amount_limit = limits[0]["amountLimit"]
                else:
                    amount_limit = 500
            else:
                amount_limit = 500
        else:
            print("[WARN] Could not fetch voucher group amount limit, using default.")
            amount_limit = 500  # fallback default
    except Exception as e:
        print(f"[WARN] Exception fetching voucher group amount limit: {e}")
        amount_limit = 500

    if amount_limit == 0:
        amount_limit = 500 

    # Step 5: Prepare voucher group data
    requested_amount = int(voucher_params2.get("amount", 500))
    final_amount = min(requested_amount, amount_limit)
    voucher_url = f"{controller_url}/openapi/v1/{OMADA_ID}/sites/{omada_site_id}/hotspot/voucher-groups"
    voucher_group_name = voucher_params2.get("name") or random_voucher_group_name()
    voucher_data = {
        "name": voucher_group_name,
        "amount": final_amount,
        "codeLength": int(voucher_params2.get("code_length",10)),
        "codeForm": voucher_params2.get("code_form",[0,1]),
        "limitType": int(voucher_params2.get("limit_type",0)),
        "limitNum": int(voucher_params2.get("limit_num",1)),
        "durationType": int(voucher_params2.get("duration_type",1)),
        "duration": int(voucher_params.get("duration")),
        "timingType": int(voucher_params2.get("timing_type",0)),
        "rateLimit": {
            "mode": int(voucher_params2.get("rate_limit_mode",0)),
            "rateLimitProfileId": voucher_params2.get("rate_limit_profile_id"),
            "customRateLimit": {
                "downLimitEnable": bool(voucher_params2.get("down_limit_enable",True)),
                "downLimit": int(voucher_params2.get("down_limit",5120)),
                "upLimitEnable": bool(voucher_params2.get("up_limit_enable",True)),
                "upLimit": int(voucher_params2.get("up_limit",5120))
            },
        },
        "trafficLimitEnable": False,
        "unitPrice": int(voucher_params.get("unit_price")),
        "currency": "PHP",
        "applyToAllPortals": bool(voucher_params2.get("apply_to_all_portals",True)),
        "logout": bool(voucher_params2.get("logout",False)),
        "validityType": int(voucher_params2.get("validity_type",0)),
    }
    voucher_data = {k: v for k, v in voucher_data.items() if v is not None}

        # Step 6: Create voucher group
    try:
        response = session.post(voucher_url, json=voucher_data, timeout=10)
        if response.status_code != 200:
            print(f"[FAIL] Voucher generation failed: {response.status_code}")
            return False, []
        result = response.json()
        if result.get('errorCode') != 0:
            print(f"[FAIL] Voucher generation API error: {result.get('msg')}")
            # Special handling for error code 42010 (e.g., too many voucher groups)
            if result.get('errorCode') == 42010:
                try:
                    group_url = f"{controller_url}/openapi/v1/{OMADA_ID}/sites/{omada_site_id}/hotspot/voucher-groups"
                    response = session.get(group_url, timeout=10)
                    if response.status_code != 200:
                        print(f"[FAIL] Failed to fetch group IDs: {response.status_code}")
                        return False, []
                    group_list = response.json().get('result', [])
                    group_info = []
                    for g in group_list:
                        group_id = g.get('id')
                        unused = g.get('unused')
                        if group_id and unused == 0:
                            group_info.append({"id": group_id})
                    if group_info:
                        delete_url = f"{controller_url}/openapi/v1/{OMADA_ID}/sites/{omada_site_id}/hotspot/voucher-groups/batch/delete"
                        del_response = session.post(delete_url, json=group_info, timeout=10)
                        if del_response.status_code == 200:
                            print(f"[OK] Deleted {len(group_info)} fully used voucher groups. Retrying voucher generation...")
                            if not retry:
                                return create_omada_vouchers_via_api(site_id, voucher_params, retry=True)
                            else:
                                print("[FAIL] Retry already attempted, aborting to prevent infinite loop.")
                        else:
                            print(f"[FAIL] Failed to delete fully used voucher groups: {del_response.status_code}")
                    else:
                        print("[INFO] No fully used voucher groups to delete.")
                except Exception as e:
                    print(f"[FAIL] Exception during voucher group cleanup: {e}")
            return False, []
        group_id = result.get('result', {}).get('id')
        print(f"[OK] Voucher group created with ID")
    except Exception as e:
        print(f"[FAIL] Error generating vouchers: {e}")
        return False, []

    # Step 7: Fetch voucher codes from the created group
    try:
        vouchers_url = f"{controller_url}/openapi/v1/{OMADA_ID}/sites/{omada_site_id}/hotspot/voucher-groups/{group_id}/print-unused"
        response = session.get(vouchers_url, timeout=10)
        if response.status_code != 200:
            print(f"[FAIL] Failed to fetch voucher codes: {response.status_code}")
            return False, []
        result = response.json()
        if result.get('errorCode') != 0:
            print(f"[FAIL] Failed to fetch voucher codes: {result.get('msg')}")
            return False, []
    
        # --- FIX: Handle both dict and list structures ---
        voucher_list = []
        res = result.get('result')
        if isinstance(res, list):
            voucher_list = res
        elif isinstance(res, dict):
            voucher_list = res.get('data', [])
        else:
            print(f"[FAIL] Unexpected result structure for voucher codes: {type(res)}")
            return False, []
    
        voucher_infos = []
        UP = voucher_params.get("unit_price")
        D = voucher_params.get("duration")
        for v in voucher_list:
            code = v.get('code')
            if code:
                voucher_infos.append({
                    "code": code,
                    "price": v.get("unitPrice", UP),
                    "duration": v.get("duration", D),
                    "group_id": group_id
                })
        print(f"[OK] Retrieved {len(voucher_infos)} voucher codes.")
    except Exception as e:
        print(f"[FAIL] Error fetching voucher codes: {e}")
        return False, []
    
    # Step 8: Store vouchers in DB
    if store_voucher_codes(site_id, voucher_infos):
        print(f"[OK] Stored {len(voucher_infos)} vouchers in the database.")
        return True, [v["code"] for v in voucher_infos]
    else:
        print("[FAIL] Failed to store vouchers in the database.")
        return False, []
    
def cleanup_expired_vouchers(site_id):
    """Clean up old used vouchers"""
    try:
        site_name = get_site_name_by_id(site_id)
        if not site_name:
            raise ValueError(f"No site_name found for site_id: {site_id}")
        db_path = f"{SITE_DB_PREFIX}{safe_site_name(site_name)}.db"
        if not os.path.exists(db_path):
            return False

        conn = get_db(db_path)
        c = conn.cursor()
        
        # Get all price tables
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'price_%'")
        price_tables = c.fetchall()
        
        cleanup_count = 0
        
        for table_row in price_tables:
            table_name = table_row['name']
            
            # Delete old used vouchers
            c.execute(f"DELETE FROM {table_name} WHERE used=1")
            cleanup_count += c.rowcount
        
        conn.commit()
        conn.close()
        
        # Also cleanup from Omada Controller
        delete_fully_used_voucher_groups(site_id)
        
        print(f"Cleaned up {cleanup_count} used vouchers for site {site_id}")
        return True
        
    except Exception as e:
        print(f"Error cleaning up vouchers: {e}")
        return False