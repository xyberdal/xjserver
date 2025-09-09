import sqlite3
import hashlib
from datetime import datetime
import os
import re
from cryptography.fernet import Fernet


DATABASE = os.path.join(os.path.dirname(__file__), 'xjserver.db')
SITE_DB_PREFIX = 'site_'

# ALIGN WITH OMADA_API.PY - Environment variable encryption
FERNET_KEY = os.environ.get('XJSERVER_ENCRYPT_KEY')
if not FERNET_KEY:
    raise RuntimeError("❌ XJSERVER_ENCRYPT_KEY environment variable is not set. Please set it in your environment or systemd service.")

if isinstance(FERNET_KEY, str):
    cipher_suite = Fernet(FERNET_KEY.encode())
else:
    cipher_suite = Fernet(FERNET_KEY)



def hash_lookup_value(value):
    """Deterministically hash a value for lookup fields (e.g., MAC address)."""
    if value is None:
        return None
    return hashlib.sha256(str(value).encode()).hexdigest()

def encrypt(data):
    """Encrypt sensitive data - compatible with omada_api.py"""
    if data is None:
        return None
    return cipher_suite.encrypt(str(data).encode()).decode()

def decrypt(encrypted_data):
    """Decrypt sensitive data - compatible with omada_api.py"""
    if encrypted_data is None:
        return None
    return cipher_suite.decrypt(encrypted_data.encode()).decode()

def normalize_mac(mac):
    """Normalize MAC address to uppercase with colons and no whitespace."""
    return mac.strip().upper() if mac else None

def safe_site_name(site_name):
    """Sanitize site name for use in file/table names."""
    return re.sub(r'[^A-Za-z0-9_\-]', '_', site_name.strip())

def get_db(db_path=None):
    """Get database connection with row factory - compatible with omada_api.py"""
    if db_path is None:
        db_path = DATABASE
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def get_site_db(site_id):
    """Get connection to site-specific database using site name."""
    site_name = get_site_name_by_id(site_id)
    if not site_name:
        raise ValueError(f"No site_name found for site_id: {site_id}")
    db_path = f"{SITE_DB_PREFIX}{safe_site_name(site_name)}.db"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def get_site_name_by_id(site_id):
    """Fetch the site name for a given site_id from the main DB."""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT site_name FROM sites WHERE site_id = ?", (site_id,))
    row = c.fetchone()
    conn.close()
    return row['site_name'] if row else None

def create_site_database(site_name):
    """Create site-specific database with required tables and price tables for all mapped amounts. Also cleans up obsolete price tables."""
    try:
        db_path = f"{SITE_DB_PREFIX}{safe_site_name(site_name)}.db"
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        # Fetch all valid amounts from duration_mappings in the main DB
        main_conn = get_db()
        main_c = main_conn.cursor()
        main_c.execute("SELECT DISTINCT amount FROM duration_mappings")
        amounts = [int(row['amount']) for row in main_c.fetchall()]
        main_conn.close()

        # Create a price table for each valid amount
        for amount in amounts:
            conn.execute(f'''CREATE TABLE IF NOT EXISTS price_{int(amount)} (
                site_id TEXT,
                price INTEGER,
                duration INTEGER,
                code TEXT PRIMARY KEY,
                used INTEGER DEFAULT 0,
                date_created TEXT DEFAULT CURRENT_TIMESTAMP,
                date_used TEXT,
                group_id TEXT
            )''')

        # --- Cleanup: Drop obsolete price tables not in duration_mappings ---
        c = conn.cursor()
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'price_%'")
        price_tables = [row['name'] for row in c.fetchall()]
        valid_table_names = {f"price_{int(amount)}" for amount in amounts}
        deleted_tables = 0
        for table in price_tables:
            if table not in valid_table_names:
                c.execute(f"DROP TABLE IF EXISTS {table}")
                deleted_tables += 1
                print(f"Deleted obsolete table: {table}")

        conn.commit()
        conn.close()
        print(f"✅ Created site database: {db_path} with price tables for all mapped amounts. Deleted {deleted_tables} obsolete tables.")
        return db_path

    except Exception as e:
        print(f"❌ Error creating site database: {e}")
        return None

def create_price_table(site_id, price):
    """Create price table in site database - EXACT match with omada_api.py"""
    try:
        # Get the site name from the site_id
        site_name = get_site_name_by_id(site_id)
        if not site_name:
            print(f"❌ Site name not found for site_id: {site_id}")
            return False

        db_path = f"{SITE_DB_PREFIX}{safe_site_name(site_name)}.db"
        # Create site database if it doesn't exist
        if not os.path.exists(db_path):
            create_site_database(site_name)
        
        conn = get_site_db(site_id)
        c = conn.cursor()
        # Create price table with EXACT structure from omada_api.py
        c.execute(f'''CREATE TABLE IF NOT EXISTS price_{int(price)} (
            site_id TEXT,
            price INTEGER,
            duration INTEGER,
            code TEXT PRIMARY KEY,
            used INTEGER DEFAULT 0,
            date_created TEXT DEFAULT CURRENT_TIMESTAMP,
            date_used TEXT,
            group_id TEXT     
        )''')
        
        conn.commit()
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Error creating price table: {e}")
        return False
    
def get_voucher_from_site_db(site_id, price):
    """Get unused voucher from site database - OMADA_API.PY COMPATIBLE"""
    try:
        site_name = get_site_name_by_id(site_id)
        if not site_name:
            raise ValueError(f"No site_name found for site_id: {site_id}")
        db_path = f"{SITE_DB_PREFIX}{safe_site_name(site_name)}.db"
        if not os.path.exists(db_path):
            print(f"⚠️  Site database {db_path} does not exist")
            return None
        
        conn = get_site_db(site_id)
        c = conn.cursor()
        
        # Get unused voucher
        c.execute(f'SELECT code FROM price_{int(price)} WHERE used = 0 LIMIT 1')
        row = c.fetchone()
        
        if row:
            voucher_code = row['code']
            # Mark as used
            c.execute(f'UPDATE price_{int(price)} SET used = 1, date_used = ? WHERE code = ?', 
                     (datetime.now().isoformat(), voucher_code))
            conn.commit()
            conn.close()
            return voucher_code
        
        conn.close()
        return None
        
    except Exception as e:
        print(f"❌ Error getting voucher from site DB: {e}")
        return None

def store_voucher_codes(site_id, voucher_infos):
    """Store voucher codes in site database - OMADA_API.PY COMPATIBLE"""
    try:
        site_name = get_site_name_by_id(site_id)
        if not site_name:
            print(f"Site name for site_id {site_id} not found in main DB.")
            return False

        db_path = f"{SITE_DB_PREFIX}{safe_site_name(site_name)}.db"
        if not os.path.exists(db_path):
            print(f"Site DB {db_path} does not exist.")
            return False

        conn_site = get_db(db_path)
        c = conn_site.cursor()
        stored_count = 0
        # Ensure price table exists
        for v in voucher_infos:
            # Ensure price table exists for this price (with group_id column)
            c.execute(f'''CREATE TABLE IF NOT EXISTS price_{int(v['price'])} (
                site_id TEXT,
                price INTEGER,
                duration INTEGER,
                code TEXT PRIMARY KEY,
                used INTEGER DEFAULT 0,
                date_created TEXT DEFAULT CURRENT_TIMESTAMP,
                date_used TEXT,
                group_id TEXT  
            )''')
            try:
                table_name = f"price_{int(v['price'])}"
                c.execute(
                    f"INSERT INTO {table_name} (site_id, price, duration, code, group_id) VALUES (?, ?, ?, ?, ?)",
                    (site_id, v["price"], v["duration"], encrypt(v["code"]), v["group_id"])
                )
                stored_count += 1
            except sqlite3.IntegrityError:
                print(f"INFO: Duplicate code skipped: {v['code']}")
                pass
            except Exception as e:
                print(f"❌ Error storing a voucher: {e} | Voucher: {v}")
        
        conn_site.commit()
        conn_site.close()
        print(f"✅ Stored {stored_count} vouchers in site_{site_id}.db")
        return stored_count > 0

    except Exception as e:
        print(f"❌ Error storing voucher codes: {e}")
        return False
        
def get_voucher_stats_local(site_id):
    """Local implementation of voucher stats using coin_logs for used/revenue, price tables for unused, keyed by site_id."""
    try:
        site_name = get_site_name_by_id(site_id)
        if not site_name:
            print(f"❌ No site_name found for site_id: {site_id}")
            return None

        db_path = f"{SITE_DB_PREFIX}{safe_site_name(site_name)}.db"
        if not os.path.exists(db_path):
            return None

        conn = get_site_db(site_id)
        c = conn.cursor()

        # Get all price tables
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'price_%'")
        price_tables = c.fetchall()

        stats = {}
        total_unused = 0

        for table_row in price_tables:
            table_name = table_row['name']
            price = int(table_name.split('_')[1])

            # Count unused vouchers
            c.execute(f"SELECT COUNT(*) FROM {table_name} WHERE used=0")
            unused_count = c.fetchone()[0]

            stats[price] = {
                'unused': unused_count,
                'used': 0,  # will be filled below from coin_logs
                'total': unused_count
            }

            total_unused += unused_count

        conn.close()

        # Now get used vouchers and revenue from coin_logs in the main DB
        conn_main = get_db()
        c_main = conn_main.cursor()
        c_main.execute("""
            SELECT amount, COUNT(*) as used_count, SUM(amount) as revenue
            FROM coin_logs
            WHERE site_id = ?
            GROUP BY amount
        """, (site_id,))
        total_used = 0
        total_revenue = 0
        for row in c_main.fetchall():
            price = row['amount']  # Use amount as the price key
            used_count = row['used_count']
            revenue = row['revenue'] or 0
            if price in stats:
                stats[price]['used'] = used_count
                stats[price]['total'] += used_count
            else:
                stats[price] = {'unused': 0, 'used': used_count, 'total': used_count}
            total_used += used_count
            total_revenue += revenue
        conn_main.close()

        return {
            'site_id': site_id,
            'site_name': site_name,
            'by_price': stats,
            'total_unused': total_unused,
            'total_used': total_used,
            'total_revenue': total_revenue,
            'total_all': total_unused + total_used
        }

    except Exception as e:
        print(f"❌ Error getting local voucher stats: {e}")
        return None

def get_voucher_stats_all_sites():
    """Get voucher statistics for all sites using site_id as key."""
    try:
        all_stats = {}
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT site_id FROM sites")
        site_ids = [row['site_id'] for row in c.fetchall()]
        conn.close()
        for site_id in site_ids:
            stats = get_voucher_stats_local(site_id)
            if stats:
                all_stats[site_id] = stats
        return all_stats
    except Exception as e:
        print(f"❌ Error getting voucher stats: {e}")
        return {}

def cleanup_used_vouchers(site_id, days_old=30):
    """Clean up old used vouchers from site database - OMADA_API.PY COMPATIBLE"""
    try:
        site_name = get_site_name_by_id(site_id)
        if not site_name:
            raise ValueError(f"No site_name found for site_id: {site_id}")
        db_path = f"{SITE_DB_PREFIX}{safe_site_name(site_name)}.db"
        if not os.path.exists(db_path):
            return False
        
        conn = get_site_db(site_id)
        c = conn.cursor()
        
        # Get all price tables
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'price_%'")
        price_tables = c.fetchall()
        
        cleanup_count = 0
        
        for table_row in price_tables:
            table_name = table_row['name']
            
            # Delete old used vouchers
            c.execute(f"DELETE FROM {table_name} WHERE used = 1 AND date_used < datetime('now', '-{days_old} days')")
            cleanup_count += c.rowcount
        
        conn.commit()
        conn.close()
        
        print(f"✅ Cleaned up {cleanup_count} used vouchers from site {site_id}")
        return True
        
    except Exception as e:
        print(f"❌ Error cleaning up vouchers: {e}")
        return False

def add_api_voucher_params(client_id, client_secret, omada_id, controller_mac, controller_port='443'):
    """Add API voucher parameters - OMADA_API.PY COMPATIBLE"""
    try:
        conn = get_db()
        c = conn.cursor()
        
        # Encrypt sensitive data
        encrypted_client_id = encrypt(client_id)
        encrypted_client_secret = encrypt(client_secret)
        
        c.execute('''INSERT INTO api_voucher_params 
                    (client_id, client_secret, omada_id, controller_mac, controller_port) 
                    VALUES (?, ?, ?, ?, ?)''',
                 (encrypted_client_id, encrypted_client_secret, omada_id, controller_mac, controller_port))
        
        conn.commit()
        conn.close()
        print("✅ API voucher parameters added successfully")
        return True
        
    except Exception as e:
        print(f"❌ Error adding API voucher parameters: {e}")
        return False


def add_site(site_id, site_name):
    """Add a new site - ENHANCED with site database creation"""
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO sites (site_id, site_name) VALUES (?, ?)", (site_id, site_name))
        conn.commit()
        
        # Also create site database for omada_api.py compatibility
        create_site_database(site_name)
        
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

from omada_api import create_omada_vouchers_via_api
# ===== KEEP ALL EXISTING FUNCTIONS FROM ORIGINAL DATABASE.PY =====

def get_all_sites(auto_create=False):
    """Get all sites, optionally auto-create if none exist"""
    print(f"DEBUG: connecting db to get sites")
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM sites ORDER BY site_name")
    sites = c.fetchall()
    conn.close()
    if not sites:
        print(f"DEBUG: No sites found in database.")
        if auto_create:
            print(f"DEBUG: Acquiring sites in Omada Controller")
            create_omada_vouchers_via_api(site_id="0000", voucher_params={"price": 0, "duration": 0}, retry=False)
            # Optionally, re-fetch sites here
    return sites

def site_exists(site_id):
    """Check if site exists"""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM sites WHERE site_id = ?", (site_id,))
    exists = c.fetchone()[0] > 0
    conn.close()
    return exists

# ===== ESP32 DEVICE MANAGEMENT =====

def add_esp32_device(device_type, location_name, ip, mac_address=None, site_id=None, api_secret=None):
    """Add a new ESP32 device"""
    conn = get_db()
    c = conn.cursor()
    try:
        hashed_mac = hash_lookup_value(normalize_mac(mac_address)) if mac_address else None
        c.execute("""
            INSERT INTO esp32_devices (device_type, location_name, ip, mac_address, site_id, api_secret, connected, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, 1, ?)
        """, (device_type, location_name, ip, hashed_mac, site_id, api_secret, datetime.now()))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def get_adopted_esp32s():
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM esp32_devices')
    devices = []
    for row in c.fetchall():
        devices.append({
            'id': row['id'],
            'device_type': decrypt(row['device_type']),
            'location_name': decrypt(row['location_name']),
            'site_id': decrypt(row['site_id']) if row['site_id'] else None,
            'portal_id': decrypt(row['portal_id']) if row['portal_id'] else None,
            'connected': bool(row['connected']) 
        })
    conn.close()
    return devices

def adopt_esp32(device_type, location_name, site_id, portal_id=None, mac_address=None, api_secret=None):
    """Adopt an ESP32 device to a site"""
    conn = get_db()
    c = conn.cursor()
    hashed_mac = hash_lookup_value(normalize_mac(mac_address)) if mac_address else None
    c.execute("""
        UPDATE esp32_devices 
        SET site_id = ?, portal_id = ?, mac_address = COALESCE(?, mac_address), api_secret = ?
        WHERE device_type = ? AND location_name = ?
    """, (site_id, portal_id, hashed_mac, api_secret, device_type, location_name))
    success = c.rowcount > 0
    conn.commit()
    conn.close()
    return success

def update_esp32_status(mac_hash, connected, ip=None):
    """Update ESP32 connection status using hashed MAC address"""
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        UPDATE esp32_devices 
        SET connected = ?, last_seen = ?, ip = ?
        WHERE mac_address = ?
    """, (connected, datetime.now(), ip, mac_hash))
    conn.commit()
    conn.close()

def get_esp32_by_location(location_name):
    """Get ESP32 device by location name"""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM esp32_devices WHERE location_name = ?", (location_name,))
    device = c.fetchone()
    conn.close()
    return device

def get_esp32_by_api_secret(api_secret):
    """Get ESP32 device by API secret"""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM esp32_devices WHERE api_secret = ?", (api_secret,))
    device = c.fetchone()
    conn.close()
    return device

def log_voucher_usage(voucher_code, device_type, amount, location_name):
    """Log voucher usage to voucher_usage_logs table - ESP32 COMPATIBLE"""
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        INSERT INTO voucher_usage_logs (voucher_code, device_type, amount, location_name, used_at)
        VALUES (?, ?, ?, ?, ?)
    """, (voucher_code, device_type, amount, location_name, datetime.now().isoformat()))
    conn.commit()
    conn.close()

# ===== ESP32 COIN LOGGING =====

def log_coin_activity(site_id, device_type, location_name, pulse_count, amount):
    """Log coin activity to coin_logs table - ESP32 COMPATIBLE"""
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        INSERT INTO coin_logs (site_id, device_type, location_name, pulse_count, amount)
        VALUES (?, ?, ?, ?, ?)
    """, (site_id, device_type, location_name, pulse_count, amount))
    insertion_id = c.lastrowid
    conn.commit()
    conn.close()
    return insertion_id

def get_coin_summary(site_filter=None, location_filter=None, time_filter=None):
    """Get coin insertion summary with filters and decrypted location names"""
    conn = get_db()
    c = conn.cursor()
    
    query = """
        SELECT site_id, location_name, device_type,
               COUNT(*) as insertion_count,
               SUM(amount) as total_amount,
               SUM(pulse_count) as total_pulses,
               MAX(logged_at) as last_activity
        FROM coin_logs WHERE 1=1
    """
    params = []
    
    if site_filter:
        query += " AND site_id = ?"
        params.append(site_filter)
    
    if location_filter:
        query += " AND location_name = ?"
        params.append(location_filter)
    
    if time_filter == 'today':
        query += " AND date(logged_at) = date('now')"
    elif time_filter == 'week':
        query += " AND logged_at >= datetime('now', '-7 days')"
    elif time_filter == 'month':
        query += " AND logged_at >= datetime('now', '-1 month')"
    
    query += " GROUP BY site_id, location_name, device_type ORDER BY total_amount DESC"
    
    c.execute(query, params)
    summary = []
    for row in c.fetchall():
        row = dict(row)
        try:
            row['location_name'] = decrypt(row['location_name'])
        except Exception:
            pass  # fallback: leave as is if decryption fails
        summary.append(row)
    conn.close()
    return summary

# ===== MAPPING SYSTEM =====

def save_pulse_mapping(pulse_count, amount, description=None):
    """Save pulse to amount mapping"""
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute("""
            INSERT OR REPLACE INTO pulse_mappings (pulse_count, amount, description)
            VALUES (?, ?, ?)
        """, (pulse_count, amount, description))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error saving pulse mapping: {e}")
        return False
    finally:
        conn.close()

def get_pulse_mappings():
    """Get all pulse mappings"""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM pulse_mappings ORDER BY pulse_count ASC")
    mappings = c.fetchall()
    conn.close()
    return mappings

def get_amount_by_pulse_count(pulse_count):
    """Get amount for a specific pulse count"""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT amount FROM pulse_mappings WHERE pulse_count = ?", (pulse_count,))
    row = c.fetchone()
    conn.close()
    return row['amount'] if row else None

def delete_pulse_mapping(mapping_id):
    """Delete a pulse mapping"""
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM pulse_mappings WHERE id = ?", (mapping_id,))
    success = c.rowcount > 0
    conn.commit()
    conn.close()
    return success

def save_duration_mapping(amount, duration, description=None):
    """Save duration mapping"""
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute("""
            INSERT OR REPLACE INTO duration_mappings (amount, duration, description)
            VALUES (?, ?, ?)
        """, (amount, duration, description))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error saving duration mapping: {e}")
        return False
    finally:
        conn.close()

def get_duration_mappings():
    """Get all duration mappings as a list of dicts"""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM duration_mappings ORDER BY amount ASC")
    mappings = c.fetchall()
    conn.close()
    return [dict(row) for row in mappings]  # <-- This line converts each row to a dict

def get_duration_by_amount(amount):
    """Get duration for a specific amount"""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT duration FROM duration_mappings WHERE amount = ?", (amount,))
    row = c.fetchone()
    conn.close()
    return row['duration'] if row else None

def delete_duration_mapping(mapping_id):
    """Delete a duration mapping"""
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM duration_mappings WHERE id = ?", (mapping_id,))
    success = c.rowcount > 0
    conn.commit()
    conn.close()
    return success

# ===== OMADA API PARAMETERS =====

def save_api_voucher_params(params):
    """Save API voucher parameters to database"""
    conn = get_db()
    c = conn.cursor()
    c.execute('''INSERT INTO api_voucher_params (
        amount, code_length, code_format, limit_type, limit_num,
        duration_type, timing_type, rate_limit_mode,
        down_limit_enable, down_limit, up_limit_enable, up_limit,
        traffic_limit_enable, traffic_limit, traffic_limit_frequency,
        currency, apply_to_all_portals, validity_type,
        description, print_comments, portals, expiration_time, effective_time,
        logout, schedule, client_id, client_secret, omada_id,
        controller_mac, controller_port, saved_at, controller_ip
    ) VALUES (
        :amount, :code_length, :code_format, :limit_type, :limit_num,
        :duration_type, :timing_type, :rate_limit_mode,
        :down_limit_enable, :down_limit, :up_limit_enable, :up_limit,
        :traffic_limit_enable, :traffic_limit, :traffic_limit_frequency,
        :currency, :apply_to_all_portals, :validity_type,
        :description, :print_comments, :portals, :expiration_time, :effective_time,
        :logout, :schedule, :client_id, :client_secret, :omada_id,
        :controller_mac, :controller_port, :saved_at, :controller_ip
    )''', params)
    conn.commit()
    conn.close()

def get_all_api_voucher_params():
    """Get all API voucher parameter sets"""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM api_voucher_params ORDER BY saved_at DESC")
    params = c.fetchall()
    conn.close()
    return params

def delete_api_voucher_params(param_id):
    """Delete API voucher parameters"""
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM api_voucher_params WHERE id = ?", (param_id,))
    success = c.rowcount > 0
    conn.commit()
    conn.close()
    return success

# ===== EMAIL CONFIGURATION =====

def save_email_config(username, password, recipients, daily=False, weekly=False, monthly=False, 
                     daily_cutoff='23:59', weekly_day='monday', monthly_day=1):
    """Save email configuration with encrypted password"""
    conn = get_db()
    c = conn.cursor()
    
    # Encrypt password
    encrypted_password = encrypt(password)
    
    c.execute("""
        INSERT OR REPLACE INTO email_config 
        (email_username, email_password, recipient_emails, daily_report, weekly_report, 
         monthly_report, daily_cutoff, weekly_day, monthly_day)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (username, encrypted_password, recipients, daily, weekly, monthly, 
          daily_cutoff, weekly_day, monthly_day))
    conn.commit()
    conn.close()

def get_email_config():
    """Get email configuration with decrypted username and password"""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM email_config ORDER BY id DESC LIMIT 1")
    config = c.fetchone()
    conn.close()
    if config:
        config = dict(config)
        if config.get('email_username'):
            config['email_username'] = decrypt(config['email_username'])
        if config.get('email_password'):
            config['email_password'] = decrypt(config['email_password'])
        if config.get('recipient_emails'):
            config['recipient_emails'] = decrypt(config['recipient_emails'])
    return config
# ===== SYSTEM CONFIGURATION =====

def save_system_config(config_key, config_value, encrypted=False, description=None):
    """Save system configuration"""
    conn = get_db()
    c = conn.cursor()
    
    if encrypted:
        config_value = encrypt(config_value)
    
    c.execute("""
        INSERT OR REPLACE INTO system_config (config_key, config_value, encrypted, description, updated_at)
        VALUES (?, ?, ?, ?, ?)
    """, (config_key, config_value, encrypted, description, datetime.now()))
    conn.commit()
    conn.close()

def get_system_config(config_key):
    """Get system configuration value"""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT config_value, encrypted FROM system_config WHERE config_key = ?", (config_key,))
    row = c.fetchone()
    conn.close()
    if row:
        if row['encrypted']:
            return decrypt(row['config_value'])
        return row['config_value']
    return None

def get_all_system_config():
    """Get all system configuration"""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM system_config ORDER BY config_key")
    configs = c.fetchall()
    conn.close()
    return configs

# ===== STATISTICS AND REPORTING =====

def get_usage_summary(site_filter=None, time_filter=None):
    """Get usage summary from voucher_usage_logs"""
    conn = get_db()
    c = conn.cursor()
    
    query = """
        SELECT vul.location_name, ed.site_id,
               COUNT(*) as voucher_count,
               SUM(vul.amount) as total_revenue,
               AVG(vul.amount) as average_transaction,
               MAX(vul.used_at) as last_activity
        FROM voucher_usage_logs vul
        LEFT JOIN esp32_devices ed ON vul.location_name = ed.location_name
        WHERE 1=1
    """
    params = []
    
    if site_filter:
        query += " AND ed.site_id = ?"
        params.append(site_filter)
    
    if time_filter == 'today':
        query += " AND date(vul.used_at) = date('now')"
    elif time_filter == 'week':
        query += " AND vul.used_at >= datetime('now', '-7 days')"
    elif time_filter == 'month':
        query += " AND vul.used_at >= datetime('now', '-1 month')"
    
    query += " GROUP BY vul.location_name, ed.site_id ORDER BY total_revenue DESC"
    
    c.execute(query, params)
    summary = c.fetchall()
    conn.close()
    return summary

def get_daily_revenue():
    """Get today's revenue from voucher usage"""
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT COALESCE(SUM(amount), 0) as revenue
        FROM coin_logs 
        WHERE date(logged_at) = date('now')
    """)
    revenue = c.fetchone()['revenue']
    conn.close()
    return revenue

def get_vouchers_used_today():
    """Return the number of vouchers used today"""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM coin_logs WHERE date(logged_at) = date('now')")
    count = c.fetchone()[0]
    conn.close()
    return count

def get_locations():
    """Get all unique ESP32 locations, decrypted if needed"""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT DISTINCT location_name FROM esp32_devices WHERE location_name IS NOT NULL ORDER BY location_name")
    locations = []
    for row in c.fetchall():
        enc_name = row['location_name']
        try:
            dec_name = decrypt(enc_name)
        except Exception:
            dec_name = enc_name  # fallback if already decrypted or error
        locations.append(dec_name)
    conn.close()
    return locations

# ===== DATABASE MAINTENANCE =====

def cleanup_old_logs(days=30):
    """Clean up old logs"""
    conn = get_db()
    c = conn.cursor()
    
    # Clean up old coin logs
    c.execute("DELETE FROM coin_logs WHERE logged_at < datetime('now', '-{} days')".format(days))
    coin_deleted = c.rowcount
    
    # Clean up old voucher usage logs
    c.execute("DELETE FROM voucher_usage_logs WHERE used_at < datetime('now', '-{} days')".format(days))
    usage_deleted = c.rowcount
    
    conn.commit()
    conn.close()
    
    return coin_deleted, usage_deleted

def vacuum_database():
    """Optimize database"""
    conn = get_db()
    conn.execute("VACUUM")
    conn.close()

def get_database_stats():
    conn = get_db()
    c = conn.cursor()
    stats = {}

    c.execute('SELECT COUNT(*) FROM sites')
    stats['sites_count'] = c.fetchone()[0]

    c.execute('SELECT COUNT(*) FROM esp32_devices')
    stats['esp32_devices'] = c.fetchone()[0]

    # Aggregate voucher stats from all site databases
    all_site_stats = get_voucher_stats_all_sites()
    stats['total_vouchers'] = sum(
        site_stats['total_all'] for site_stats in all_site_stats.values()
    )

    stats['today_revenue'] = get_daily_revenue()
    stats['vouchers_used_today'] = get_vouchers_used_today()

    conn.close()
    return stats

# Initialize database on import
if __name__ == "__main__":
    init_db()
    print("✅ Database initialized!")