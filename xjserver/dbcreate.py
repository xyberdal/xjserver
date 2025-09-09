import os
import sqlite3

DATABASE = os.path.join(os.path.dirname(__file__), 'xjserver.db')

def get_db():
    conn = sqlite3.connect(DATABASE)
    return conn

def init_db():
    """Initialize all database tables"""
    print("Initializing database at:", DATABASE)
    conn = get_db()
    c = conn.cursor()

    # Enable foreign keys
    c.execute("PRAGMA foreign_keys = ON")

    # ===== CORE SYSTEM TABLES =====

    # Sites table - Multi-tenant organization
    c.execute("""
        CREATE TABLE IF NOT EXISTS sites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site_id TEXT UNIQUE NOT NULL,
            site_name TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')

    # ESP32 devices table - Device management with API secrets
    c.execute("""
        CREATE TABLE IF NOT EXISTS esp32_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_type TEXT NOT NULL,
            location_name TEXT UNIQUE NOT NULL,
            site_id TEXT,
            portal_id TEXT,
            api_secret TEXT,
            mac_address TEXT UNIQUE NOT NULL,
            ws_token TEXT,
            ip TEXT,
            connected BOOLEAN DEFAULT 0,
            last_seen DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            publickey TEXT,
            FOREIGN KEY (site_id) REFERENCES sites (site_id)
        )
    """)

    # Voucher usage logs table - ESP32 activity tracking
    c.execute("""
        CREATE TABLE IF NOT EXISTS voucher_usage_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            voucher_code TEXT NOT NULL,
            device_type TEXT NOT NULL,
            amount REAL NOT NULL,
            location_name TEXT NOT NULL,
            used_at DATETIME NOT NULL,
            FOREIGN KEY (location_name) REFERENCES esp32_devices (location_name)
        )
    """)

    # Coin logs table - ESP32 coin insertion tracking
    c.execute("""
        CREATE TABLE IF NOT EXISTS coin_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site_id TEXT,
            device_type TEXT,
            location_name TEXT NOT NULL,
            pulse_count INTEGER,
            amount REAL NOT NULL,
            duration INTEGER,
            logged_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (location_name) REFERENCES esp32_devices (location_name),
            FOREIGN KEY (site_id) REFERENCES sites (site_id)
        )
    """)

    # ===== MAPPING SYSTEM =====

    # Pulse mappings table - Coin pulse to amount conversion
    c.execute("""
        CREATE TABLE IF NOT EXISTS pulse_mappings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pulse_count INTEGER UNIQUE NOT NULL,
            amount INTEGER NOT NULL,
            description TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Check if duration_mappings table exists before creation
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='duration_mappings'")
    duration_table_exists = c.fetchone() is not None

    # Duration mappings table - Amount to duration conversion
    c.execute("""
        CREATE TABLE IF NOT EXISTS duration_mappings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            amount INTEGER NOT NULL,
            duration INTEGER NOT NULL,
            description TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(amount)
        )
    """)

    # Only insert default duration mappings if table did NOT exist before
    if not duration_table_exists:
        c.execute("INSERT INTO duration_mappings (amount, duration, description) VALUES (5, 180, '3 hours WiFi access')")
        c.execute("INSERT INTO duration_mappings (amount, duration, description) VALUES (10, 420, '7 hours WiFi access')")
        c.execute("INSERT INTO duration_mappings (amount, duration, description) VALUES (15, 840, '14 hours WiFi access')")
        c.execute("INSERT INTO duration_mappings (amount, duration, description) VALUES (20, 1440, '24 hours WiFi access')")

    # ===== API voucher parameters table =====
    c.execute("""
        CREATE TABLE IF NOT EXISTS api_voucher_params (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT,
            client_secret TEXT,
            omada_id TEXT,
            controller_mac TEXT,
            controller_port TEXT DEFAULT '8043',
            -- Extended fields for comprehensive voucher generation
            amount INTEGER DEFAULT 500,
            code_length INTEGER DEFAULT 10,
            code_format TEXT DEFAULT '[0,1]',
            limit_type INTEGER DEFAULT 0,
            limit_num INTEGER DEFAULT 1,
            duration_type INTEGER DEFAULT 0,
            timing_type INTEGER DEFAULT 0,
            rate_limit_mode INTEGER DEFAULT 0,
            down_limit_enable TEXT DEFAULT 'false',
            down_limit INTEGER DEFAULT 0,
            up_limit_enable TEXT DEFAULT 'false',
            up_limit INTEGER DEFAULT 0,
            traffic_limit_enable TEXT DEFAULT 'false',
            traffic_limit INTEGER DEFAULT 0,
            traffic_limit_frequency INTEGER DEFAULT 0,
            currency TEXT DEFAULT 'PHP',
            apply_to_all_portals TEXT DEFAULT 'true',
            validity_type INTEGER DEFAULT 0,
            description TEXT DEFAULT 'Generated Vouchers',
            print_comments TEXT DEFAULT '',
            portals TEXT DEFAULT '[]',
            expiration_time TEXT DEFAULT NULL,
            effective_time TEXT DEFAULT NULL,
            logout TEXT DEFAULT 'false',
            schedule TEXT DEFAULT NULL,
            saved_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            controller_ip TEXT
        )
    """)

    # ===== SYSTEM CONFIGURATION =====

    # Email configuration table - Reporting system
    c.execute("""
        CREATE TABLE IF NOT EXISTS email_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email_username TEXT,
            email_password TEXT,
            recipient_emails TEXT,
            daily_report BOOLEAN DEFAULT 0,
            weekly_report BOOLEAN DEFAULT 0,
            monthly_report BOOLEAN DEFAULT 0,
            daily_cutoff TEXT DEFAULT '23:59',
            weekly_day TEXT DEFAULT 'monday',
            monthly_day INTEGER DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # System configuration table - General settings
    c.execute("""
        CREATE TABLE IF NOT EXISTS system_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            config_key TEXT UNIQUE NOT NULL,
            config_value TEXT NOT NULL,
            encrypted BOOLEAN DEFAULT 0,
            description TEXT,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    c.execute("INSERT OR IGNORE INTO pulse_mappings (pulse_count, amount, description) VALUES (1, 1, 'Pulse 1 = Value 1')")
    c.execute("INSERT OR IGNORE INTO pulse_mappings (pulse_count, amount, description) VALUES (5, 5, 'Pulse 5 = Value 5')")
    c.execute("INSERT OR IGNORE INTO pulse_mappings (pulse_count, amount, description) VALUES (10, 10, 'Pulse 10 = Value 10')")
    c.execute("INSERT OR IGNORE INTO pulse_mappings (pulse_count, amount, description) VALUES (20, 20, 'Pulse 20 = Value 20')")

    conn.commit()
    conn.close()
    print("✅ Database initialized")