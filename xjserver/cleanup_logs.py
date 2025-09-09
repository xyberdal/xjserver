import sqlite3
import os
import shutil
import glob
from datetime import datetime, timedelta
from cryptography.fernet import Fernet

# Database paths
MAIN_DB = 'xjserver.db'  # FIXED: Changed from 'vouchers.db'
SITE_DB_PREFIX = 'site_'

# Cleanup thresholds
CUTOFF_DAYS = 547  # 1.5 years ≈ 547 days
SIX_MONTHS_DAYS = 183  # 6 months ≈ 183 days
THREE_MONTHS_DAYS = 90  # 3 months for critical cleanup
ONE_MONTH_DAYS = 30  # 1 month for emergency cleanup

# Disk usage thresholds
DISK_WARNING_THRESHOLD = 70  # Start aggressive cleanup
DISK_CRITICAL_THRESHOLD = 85  # Emergency cleanup
DISK_EMERGENCY_THRESHOLD = 95  # Delete everything old

# --- Encryption Key ---
FERNET_KEY = os.environ.get('XJSERVER_ENCRYPT_KEY')
if not FERNET_KEY:
    raise RuntimeError("XJSERVER_ENCRYPT_KEY not set in environment (systemd)")
fernet = Fernet(FERNET_KEY.encode() if isinstance(FERNET_KEY, str) else FERNET_KEY)

def encrypt(val):
    if val is None:
        return None
    return fernet.encrypt(val.encode()).decode()

def decrypt(val):
    if val is None:
        return None
    return fernet.decrypt(val.encode()).decode()

def disk_usage_percent(path='/'):
    """Get disk usage percentage"""
    try:
        total, used, free = shutil.disk_usage(path)
        return used / total * 100
    except Exception as e:
        print(f"Error getting disk usage: {e}")
        return 0

def get_db_size(db_path):
    """Get database file size in MB"""
    try:
        if os.path.exists(db_path):
            return os.path.getsize(db_path) / (1024 * 1024)
        return 0
    except Exception:
        return 0

def cleanup_main_database_logs(cutoff_days):
    """Clean up logs in main database"""
    cutoff = (datetime.now() - timedelta(days=cutoff_days)).isoformat()
    
    try:
        with sqlite3.connect(MAIN_DB) as conn:  # FIXED: Uses MAIN_DB constant
            c = conn.cursor()
            
            # Clean up voucher usage logs
            c.execute("DELETE FROM voucher_usage_logs WHERE used_at < ?", (cutoff,))
            usage_deleted = c.rowcount
            
            # Clean up coin logs
            c.execute("DELETE FROM coin_logs WHERE logged_at < ?", (cutoff,))
            coin_deleted = c.rowcount
            
            conn.commit()
            
            # Optimize database
            c.execute("VACUUM")
            
        print(f"Main DB cleanup (older than {cutoff_days} days):")
        print(f"  - Voucher usage logs: {usage_deleted}")
        print(f"  - Coin logs: {coin_deleted}")
        
        return True
        
    except Exception as e:
        print(f"Main database cleanup failed: {e}")
        return False

def cleanup_site_databases(cutoff_days):
    """Clean up used vouchers from site databases"""
    site_dbs = glob.glob(f"{SITE_DB_PREFIX}*.db")
    total_cleaned = 0
    
    for db_path in site_dbs:
        try:
            site_id = db_path.replace(SITE_DB_PREFIX, '').replace('.db', '')
            
            with sqlite3.connect(db_path) as conn:
                c = conn.cursor()
                
                # Get all price tables
                c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'price_%'")
                price_tables = c.fetchall()
                
                site_cleaned = 0
                for table_row in price_tables:
                    table_name = table_row[0]
                    
                    # Delete used vouchers
                    c.execute(f"DELETE FROM {table_name} WHERE used = 1")
                    site_cleaned += c.rowcount
                
                conn.commit()
                c.execute("VACUUM")
                
                if site_cleaned > 0:
                    print(f"  - Site {site_id}: {site_cleaned} used vouchers")
                    total_cleaned += site_cleaned
                    
        except Exception as e:
            print(f"Error cleaning site database {db_path}: {e}")
    
    if total_cleaned > 0:
        print(f"Site databases: {total_cleaned} used vouchers cleaned")
    
    return total_cleaned

def cleanup_system_files():
    """Clean up system files and temporary data"""
    cleaned_files = 0
    
    try:
        # Clean up any temporary files
        temp_patterns = ['*.tmp', '*.log', '*.bak', '*~']
        
        for pattern in temp_patterns:
            for file_path in glob.glob(pattern):
                try:
                    os.remove(file_path)
                    cleaned_files += 1
                    print(f"  - Removed temp file: {file_path}")
                except Exception as e:
                    print(f"  - Could not remove {file_path}: {e}")
        
        # Clean up old database backups (keep only 3 most recent)
        backup_files = glob.glob("xjserver.db.backup*")  # FIXED: Use correct database name
        backup_files.sort(key=os.path.getmtime, reverse=True)
        
        for old_backup in backup_files[3:]:  # Keep only 3 most recent
            try:
                os.remove(old_backup)
                cleaned_files += 1
                print(f"  - Removed old backup: {old_backup}")
            except Exception as e:
                print(f"  - Could not remove backup {old_backup}: {e}")
                
    except Exception as e:
        print(f"Error cleaning system files: {e}")
    
    return cleaned_files

def get_cleanup_summary():
    """Get summary of database sizes and disk usage"""
    print("\n" + "="*50)
    print("CLEANUP SUMMARY")
    print("="*50)
    
    # Disk usage
    disk_usage = disk_usage_percent('/')
    print(f"Disk Usage: {disk_usage:.1f}%")
    
    # Main database size
    main_db_size = get_db_size(MAIN_DB)  # FIXED: Use MAIN_DB constant
    print(f"Main Database (xjserver.db): {main_db_size:.2f} MB")  # FIXED: Show correct name
    
    # Site databases
    site_dbs = glob.glob(f"{SITE_DB_PREFIX}*.db")
    total_site_size = sum(get_db_size(db) for db in site_dbs)
    print(f"Site Databases: {len(site_dbs)} files, {total_site_size:.2f} MB total")
    
    print(f"Total Database Size: {main_db_size + total_site_size:.2f} MB")
    print("="*50)

def perform_cleanup():
    """Main cleanup function with intelligent thresholds"""
    print("🧹 Starting XJServer Database Cleanup...")
    print(f"Timestamp: {datetime.now().isoformat()}")
    
    disk_usage = disk_usage_percent('/')
    print(f"Current disk usage: {disk_usage:.1f}%")
    
    cleanup_performed = False
    
    if disk_usage >= DISK_EMERGENCY_THRESHOLD:
        print(f"🚨 EMERGENCY: Disk usage {disk_usage:.1f}% >= {DISK_EMERGENCY_THRESHOLD}%")
        print("Performing aggressive cleanup...")
        
        # Emergency cleanup - keep only 1 week of data
        cleanup_main_database_logs(7)
        cleanup_site_databases(7)
        cleanup_system_files()
        cleanup_performed = True
        
    elif disk_usage >= DISK_CRITICAL_THRESHOLD:
        print(f"⚠️  CRITICAL: Disk usage {disk_usage:.1f}% >= {DISK_CRITICAL_THRESHOLD}%")
        print("Performing critical cleanup...")
        
        # Critical cleanup - keep only 1 month
        cleanup_main_database_logs(ONE_MONTH_DAYS)
        cleanup_site_databases(ONE_MONTH_DAYS)
        cleanup_system_files()
        cleanup_performed = True
        
    elif disk_usage >= DISK_WARNING_THRESHOLD:
        print(f"⚠️  WARNING: Disk usage {disk_usage:.1f}% >= {DISK_WARNING_THRESHOLD}%")
        print("Performing aggressive cleanup...")
        
        # Warning cleanup - keep only 3 months
        cleanup_main_database_logs(THREE_MONTHS_DAYS)
        cleanup_site_databases(THREE_MONTHS_DAYS)
        cleanup_performed = True
        
    else:
        print("✅ Normal cleanup - keeping 1.5 years of data")
        
        # Normal cleanup - keep 1.5 years
        cleanup_main_database_logs(CUTOFF_DAYS)
        cleanup_site_databases(CUTOFF_DAYS)
        cleanup_performed = True
    
    if cleanup_performed:
        print("\n✅ Cleanup completed successfully!")
        
        # Show final disk usage
        final_disk_usage = disk_usage_percent('/')
        saved_space = disk_usage - final_disk_usage
        print(f"Final disk usage: {final_disk_usage:.1f}%")
        if saved_space > 0:
            print(f"Space saved: {saved_space:.1f}%")
        
        get_cleanup_summary()
    else:
        print("❌ No cleanup performed")

def backup_databases_before_cleanup():
    """Create backup of main database before cleanup"""
    try:
        backup_name = f"{MAIN_DB}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"  # FIXED: Use MAIN_DB
        shutil.copy2(MAIN_DB, backup_name)  # FIXED: Use MAIN_DB
        print(f"✅ Backup created: {backup_name}")
        return True
    except Exception as e:
        print(f"❌ Backup failed: {e}")
        return False

if __name__ == "__main__":
    print("🗄️  XJServer Database Cleanup Utility")
    print("====================================")
    
    # Create backup first
    if os.path.exists(MAIN_DB):  # FIXED: Use MAIN_DB constant
        print("Creating backup before cleanup...")
        backup_databases_before_cleanup()
    
    # Perform cleanup
    perform_cleanup()
    
    print("\n🎉 Cleanup process finished!")