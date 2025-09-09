from email.policy import default
import os
import time
import subprocess
import uuid
import sqlite3
import traceback
from datetime import datetime, timedelta
from flask import Blueprint, request, redirect, url_for, flash, render_template, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import database
from database import (
    get_db, encrypt, decrypt, hash_lookup_value, normalize_mac, get_all_sites,
    get_email_config, get_usage_summary, get_coin_summary,
    get_database_stats, get_adopted_esp32s,
    get_duration_mappings, create_site_database, safe_site_name, SITE_DB_PREFIX,
    get_locations, cleanup_old_logs
)

from omada_api import generate_vouchers_if_needed, get_latest_api_voucher_params, periodic_controller_ip_scan
from esp32_handlers import connections_by_location

pending_adoptions = []

def create_admin_routes(app):
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """User login"""
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            conn = get_db()
            c = conn.cursor()
            c.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
            user = c.fetchone()
            conn.close()
            if user and check_password_hash(user['password_hash'], password):
                session['logged_in'] = True
                session['username'] = username
                session.permanent = False
                flash('Logged in successfully!', 'success')
                return redirect(url_for('admin'))
            else:
                flash('Invalid username or password', 'danger')
        return render_template('login.html')
    
    @app.route('/logout')
    def logout():
        session.clear()
        return redirect(url_for('login'))
    
    @app.route('/register', methods=['GET', 'POST'])
    def register():
        """User registration (only if no users exist)"""
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM users')
        user_count = c.fetchone()[0]
        
        if user_count > 0:
            conn.close()
            flash('Registration is disabled', 'danger')
            return redirect(url_for('login'))
        
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            confirm_password = request.form['password2']

            if len(username) < 3 or len(password) < 8:
                flash('Username must be at least 3 characters and password at least 8 characters', 'danger')

            elif password != confirm_password:
                flash('Passwords do not match', 'danger')
            else:
                password_hash = generate_password_hash(password)
                c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', 
                         (username, password_hash))
                conn.commit()
                flash('User registered successfully!', 'success')
                conn.close()
                return redirect(url_for('login'))
        
        conn.close()
        return render_template('register.html')
    
    @app.route('/admin')
    def admin():
        """Main admin dashboard with Omada integration"""
    
        # Extract filters from request.args FIRST
        filter_site = request.args.get('filter_site')
        filter_location = request.args.get('filter_location')
        filter_type = request.args.get('filter_type')
        filter_time = request.args.get('filter_time')
    
        sites = get_all_sites()
        adopted_esp32s = get_adopted_esp32s()
        print("DEBUG: adopted_esp32s:", adopted_esp32s)
        usage_summary = get_usage_summary(time_filter=filter_time)
        coin_summary = get_coin_summary(site_filter=filter_site, location_filter=filter_location, time_filter=filter_time)
        locations = get_locations()
        email_config = get_email_config()
        api_params = get_latest_api_voucher_params()
        stats = get_database_stats()
        

        all_stocks = get_all_voucher_stocks()  # {site_name: {price: unused_count, ...}, ...}
        voucher_stock_summary = []
        if not all_stocks:
            print("DEBUG: No voucher stocks found")
        else:
            for site_name, price_dict in all_stocks.items():
                for price, unused in price_dict.items():
                    voucher_stock_summary.append({
                        "site_name": site_name,
                        "price": price,
                        "unused": unused
                    })
    
        return render_template('admin.html',
            sites=sites,
            adopted_esp32s=adopted_esp32s,
            usage_summary=usage_summary,
            coin_summary=coin_summary,
            locations=locations,
            email_config=email_config,
            api_params=api_params,
            stats=stats,
            site_filter=filter_site,
            location_filter=filter_location,
            time_filter=filter_time,
            voucher_stock_summary=voucher_stock_summary,
            pending_adoptions=pending_adoptions
        )
    print("DEBUG: Rendered admin dashboard")   
 
    @app.route('/pending_adoption', methods=['POST'])
    def pending_adoption():
        data = request.get_json()
        if not data:
            return jsonify({'error': 'JSON data required'}), 400
    
        device_type = data.get('device_type')
        mac_address = data.get('mac_address')
    
        if not mac_address:
            return jsonify({'error': 'mac_address required'}), 400
    
        normalized_mac = normalize_mac(mac_address)
        hashed_mac = hash_lookup_value(normalized_mac)
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT * FROM esp32_devices WHERE mac_address = ?', (hashed_mac,))
        device = c.fetchone()
    
        # If device is adopted, ensure it has a token
        if device:
            token = device['ws_token']
            if not token:
                # Generate and save a new token
                token = str(uuid.uuid4())
                c.execute('UPDATE esp32_devices SET ws_token = ? WHERE mac_address = ?', (token, hashed_mac))
                conn.commit()
                print(f"New token issued for MAC {mac_address}: {token}")
            conn.close()
            print("=== [API] adoption_status: ADOPTED ===")
            return jsonify({
                'status': 'adopted',
                'location_name': decrypt(device['location_name']),
                'ws_url': f'ws://{request.host.split(":")[0]}:8001/ws',
                'token': token
            }), 200
    
        conn.close()
    
        # Not adopted, check if already pending
        if any(dev['mac_address'] == mac_address for dev in pending_adoptions):
            print(f"Device already pending adoption: {mac_address}")
            return jsonify({'status': 'pending', 'message': 'Device already pending adoption'}), 200
    
        # If device_type is not provided, just return pending
        if not device_type:
            return jsonify({'status': 'pending', 'message': 'device_type required for new adoption'}), 400
    
        # Add to pending list
        pending_adoptions.append({
            'device_type': device_type,
            'mac_address': mac_address,
            'timestamp': datetime.now().isoformat()
        })
        print("DEBUG: pending_adoptions now:", pending_adoptions)
        return jsonify({'status': 'pending', 'message': 'Device pending admin adoption'}), 200
    @app.route('/adopt_esp32', methods=['POST'])
    def adopt_esp32():
        device_type = request.form.get('device_type')
        location_name = request.form.get('location_name')
        site_id = request.form.get('site_id')
        portal_id = request.form.get('portal_id', '') or None
        mac_address = request.form.get('mac_address')
        publickey = request.form.get('public_key')
        license_key = request.form.get('license_key')
    
        if not all([device_type, location_name, mac_address, publickey, license_key]):
            if request.is_json:
                return jsonify({'error': 'Missing required fields'}), 400
            flash('fields are required', 'danger')
            return redirect(url_for('admin'))
    
        ws_token = str(uuid.uuid4())  # Generate a one-time token
        
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute('''SELECT * FROM esp32_devices 
                         WHERE device_type=? AND location_name=?''',
                      (encrypt(device_type), encrypt(location_name)))
            existing = c.fetchone()
    
            hashed_mac = hash_lookup_value(normalize_mac(mac_address))
            
            try:
                c.execute('''INSERT INTO esp32_devices 
                    (device_type, location_name, site_id, portal_id, mac_address, ws_token, api_secret, publickey)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                    (encrypt(device_type), encrypt(location_name), 
                    encrypt(site_id) if site_id else None,
                    encrypt(portal_id) if portal_id else None,
                    hashed_mac, ws_token, license_key, publickey)
                )
                conn.commit()
                flash(f'Adopted {device_type} device at {location_name}', 'success')
            except sqlite3.IntegrityError:
                flash('Device with this location name or MAC address already exists!', 'danger')
            finally:
                conn.close()
    
            # Remove from pending_adoptions after DB operation
            pending_adoptions[:] = [dev for dev in pending_adoptions if dev['mac_address'] != mac_address]
    
        except Exception as e:
            flash(f'Error adopting device: {str(e)}', 'danger')
            return redirect(url_for('admin'))
    
        return redirect(url_for('admin'))
        from flask import Blueprint, jsonify
    
    @app.route('/api/omada/discover_ip', methods=['POST'])
    def api_omada_discover_ip():
        # Start a scan (runs in background)
        periodic_controller_ip_scan()
        time.sleep(5)  # Give it a moment to start
        params = get_latest_api_voucher_params()
        controller_ip = params.get('controller_ip') if params else None
        if controller_ip:
            return jsonify({"message": f"Controller IP discovered: {controller_ip}", "controller_ip": controller_ip})
        else:
            return jsonify({"message": "Controller IP not found. Please try again later.", "controller_ip": None})

    @app.route('/save_api_voucher_params', methods=['POST'])
    def save_api_voucher_params():
        def str_to_bool(val):
            return str(val).lower() in ['true', '1', 'yes', 'on']
    
        def safe_int(value, default=0):
            try:
                return int(value)
            except (TypeError, ValueError):
                return default
    
        params = {
            'amount': safe_int(request.form.get('amount'), 500),
            'code_length': safe_int(request.form.get('code_length'), 10),
            'code_format': request.form.get('code_format', '[0,1]'),
            'limit_type': safe_int(request.form.get('limit_type')),
            'limit_num': safe_int(request.form.get('limit_num'), 1),
            'duration_type': safe_int(request.form.get('duration_type')),
            'timing_type': safe_int(request.form.get('timing_type')),
            'rate_limit_mode': safe_int(request.form.get('rate_limit_mode')),
            'down_limit_enable': str_to_bool(request.form.get('down_limit_enable', 'false')),
            'down_limit': safe_int(request.form.get('down_limit')),
            'up_limit_enable': str_to_bool(request.form.get('up_limit_enable', 'false')),
            'up_limit': safe_int(request.form.get('up_limit')),
            'traffic_limit_enable': str_to_bool(request.form.get('traffic_limit_enable', 'false')),
            'traffic_limit': safe_int(request.form.get('traffic_limit')),
            'traffic_limit_frequency': safe_int(request.form.get('traffic_limit_frequency')),
            'currency': request.form.get('currency', 'PHP'),
            'apply_to_all_portals': str_to_bool(request.form.get('apply_to_all_portals', 'true')),
            'validity_type': safe_int(request.form.get('validity_type')),
            'description': request.form.get('description', 'Generated Vouchers'),
            'print_comments': request.form.get('print_comments', ''),
            'portals': request.form.get('portals', '[]'),
            'expiration_time': request.form.get('expiration_time'),
            'effective_time': request.form.get('effective_time'),
            'logout': str_to_bool(request.form.get('logout', 'false')),
            'schedule': request.form.get('schedule'),
            'client_id': encrypt(request.form.get('client_id', '')),
            'client_secret': encrypt(request.form.get('client_secret', '')),
            'omada_id': encrypt(request.form.get('omada_id', '')),
            'controller_mac': encrypt(normalize_mac(request.form.get('controller_mac', ''))),
            'controller_port': encrypt(request.form.get('controller_port', '')),
            'saved_at': datetime.now().isoformat(),
            'controller_ip': (request.form.get('controller_ip', ''))
        }
    
        try:
            database.save_api_voucher_params(params)
            flash('API voucher parameters saved successfully!', 'success')
            safe_params = {**params, 'client_id': '***', 'client_secret': '***'}
            print("Saved params:", safe_params)
        except Exception as e:
            flash(f'Error saving API voucher parameters: {str(e)}', 'danger')
        finally:
            print("Request handled at:", datetime.now())
    
        return redirect(url_for('admin'))

    @app.route('/api/voucher-params')
    def get_voucher_params():
        """Get latest voucher parameters for form loading"""
        try:
            params = database.get_all_api_voucher_params()
            if params:
                # Decrypt sensitive fields
                decrypted_params = dict(params)
                for field in ['client_id', 'client_secret', 'omada_id', 'controller_mac', 'controller_port']:
                    if decrypted_params.get(field):
                        try:
                            decrypted_params[field] = decrypt(decrypted_params[field])
                        except:
                            decrypted_params[field] = ''
                return jsonify(decrypted_params)
            return jsonify({})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/voucher-params/all')
    def get_all_voucher_params():
        """Get all saved voucher parameter sets for admin management"""
        try:
            all_params = database.get_all_api_voucher_params()
            
            # Decrypt sensitive fields for each parameter set
            decrypted_list = []
            for params in all_params:
                decrypted_params = dict(params)
                for field in ['client_id', 'client_secret', 'omada_id', 'controller_mac', 'controller_port']:
                    if decrypted_params.get(field):
                        try:
                            decrypted_params[field] = decrypt(decrypted_params[field])
                        except:
                            decrypted_params[field] = ''
                decrypted_list.append(decrypted_params)
            
            return jsonify(decrypted_list)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/voucher-params/delete/<int:param_id>', methods=['DELETE'])
    def delete_voucher_params(param_id):
        """Delete saved voucher parameter set"""
        try:
            success = database.delete_api_voucher_params(param_id)
            if success:
                return jsonify({'status': 'success', 'message': 'Parameter set deleted'})
            else:
                return jsonify({'status': 'error', 'message': 'Parameter set not found'}), 404
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/save_email_config', methods=['POST'])
    def save_email_config():
        """Save email configuration"""
        try:
            email_username = request.form.get('email_username', '')
            email_password = request.form.get('email_password', '')
            recipient_emails = request.form.get('recipient_emails', '')
            daily_report = 1 if request.form.get('daily_report') else 0
            weekly_report = 1 if request.form.get('weekly_report') else 0
            monthly_report = 1 if request.form.get('monthly_report') else 0
            daily_cutoff = request.form.get('daily_cutoff', '23:59')
            weekly_day = request.form.get('weekly_day', 'Sunday')
            monthly_day = int(request.form.get('monthly_day', 1))
            
            conn = get_db()
            c = conn.cursor()
            
            # Clear existing config and insert new one
            c.execute('DELETE FROM email_config')
            c.execute('''INSERT INTO email_config 
                         (email_username, email_password, recipient_emails, daily_report,
                          weekly_report, monthly_report, daily_cutoff, weekly_day,
                          monthly_day, created_at)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                     (encrypt(email_username), encrypt(email_password), encrypt(recipient_emails),
                      daily_report, weekly_report, monthly_report, daily_cutoff,
                      weekly_day, monthly_day, datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            
            flash('Email configuration saved successfully!', 'success')
            
        except Exception as e:
            flash(f'Error saving email configuration: {str(e)}', 'danger')
        
        return redirect(url_for('admin'))

    @app.route('/api/email_config')
    def api_get_email_config():
        """Get the current email configuration (only one entry expected)"""
        try:
            email_config = get_email_config()
            if email_config:
                return jsonify(email_config)
            return jsonify({})
        except Exception as e:
            return jsonify({'error': str(e)}), 500


    @app.route('/test_email', methods=['POST'])
    def test_email():
        """Test email configuration"""
        try:
            email_config = get_email_config()
            if not email_config:
                return jsonify({'success': False, 'message': 'No email configuration found'})
            
            msg = MIMEMultipart()
            msg['From'] = email_config['email_username']
            msg['To'] = email_config['recipient_emails']
            msg['Subject'] = 'Test Email from XJServer'
            msg.attach(MIMEText('This is a test email from XJServer.', 'plain'))   
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(email_config['email_username'], email_config['email_password'])
            server.send_message(msg)
            server.quit()
            return jsonify({'success': True, 'message': 'Test email sent successfully!'})
        except Exception as e:
            print("❌ Test email failed:", e)
            traceback.print_exc()
            return jsonify({'success': False, 'message': f'Email test failed: {str(e)}'})
    
    @app.route('/admin/cleanup_logs', methods=['POST'])
    def admin_cleanup_logs():
        """Clean up old logs using external script"""
        try:
            result = subprocess.run(
                ['python3', 'cleanup_logs.py'],
                cwd=os.path.dirname(os.path.abspath(__file__)),
                capture_output=True, text=True
            )
            output = result.stdout + result.stderr
            if result.returncode == 0:
                flash('Cleanup completed successfully.', 'success')
            else:
                flash(f'Cleanup failed: {output}', 'danger')
        except Exception as e:
            flash(f'Cleanup failed: {e}', 'danger')
        return redirect(url_for('admin'))
    
    @app.route('/admin/cleanup_database', methods=['POST'])
    def admin_cleanup_database():
        """Clean up old database entries"""
        try:
            days_to_keep = int(request.form.get('days_to_keep', 30))
            
            # Clean up old logs
            cleanup_result = cleanup_old_logs(days_to_keep)
            
            # Vacuum databases
            vacuum_result = vacuum_databases()
            
            message = f"""Database cleanup completed:
            - Usage logs deleted: {cleanup_result['usage_logs_deleted']}
            - Coin logs deleted: {cleanup_result['coin_logs_deleted']}
            - Sessions deleted: {cleanup_result['sessions_deleted']}
            - Databases vacuumed: {len(vacuum_result['site_dbs_vacuumed']) + 1}
            """
            
            flash(message, 'success')
            
        except Exception as e:
            flash(f'Database cleanup failed: {str(e)}', 'danger')
        
        return redirect(url_for('admin'))

    @app.route('/admin/generate_vouchers', methods=['POST'])
    def admin_generate_vouchers():
        """Manually trigger voucher generation for specific site/price"""
        try:
            site_id = request.form.get('site_id')
            price = int(request.form.get('price'))
            
            if not site_id or not price:
                flash('Site ID and price are required', 'danger')
                return redirect(url_for('admin'))
            
            # Trigger voucher generation
            success = check_voucher_count_and_generate(site_id, price)
            
            if success:
                flash(f'Voucher generation triggered for site {site_id}, price {price}', 'success')
            else:
                flash(f'Failed to generate vouchers for site {site_id}, price {price}', 'warning')
                
        except Exception as e:
            flash(f'Error generating vouchers: {str(e)}', 'danger')
        
        return redirect(url_for('admin'))

    @app.route('/admin/check_voucher_stock', methods=['POST'])
    def admin_check_voucher_stock():
        try:
            check_all_voucher_stocks_on_startup(max_retries=1, delay=1)
            return jsonify({"status": "success", "message": "Voucher stock check completed."})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500


def get_admin_routes_list():
    """Get list of admin routes for authentication check"""
    return [
        'admin', 'adopt_esp32', 'api_adopt_esp32', 'save_api_voucher_params', 
        'admin_cleanup_logs', 'save_email_config', 'test_email',
        'admin_cleanup_database', 'admin_generate_vouchers', 'admin_sync_omada',
        'admin_device_status', 'get_voucher_params', 'get_all_voucher_params',
        'delete_voucher_params'
    ]

def check_admin_session():
    """Check if user is logged in"""
    return session.get('logged_in', False)

def send_daily_report():
    """Send daily revenue report"""
    try:
        email_config = get_email_config()
        if not email_config or not email_config['daily_report']:
            return False

        stats = get_database_stats()
        
        today = datetime.now().date().isoformat()
        usage_summary = get_usage_summary(time_filter=today)
        coin_summary = get_coin_summary(time_filter=today)

        msg = MIMEMultipart()
        msg['From'] = email_config['email_username']
        msg['To'] = email_config['recipient_emails']
        msg['Subject'] = f'XJServer Daily Report - {datetime.now().strftime("%Y-%m-%d")}'
        
        body = f"""
        XJServer Daily Report for {datetime.now().strftime('%Y-%m-%d')}
        
        Summary:
        - Total Revenue: ₱{stats.today_revenue}
        - Vouchers Used: {stats.today_vouchers}
        
        Usage by Site:
        """
        
        for usage in usage_summary:
            body += f"- {usage['site_id']}: ₱{usage['total_amount']}\n"
        
        body += "\nCoin Insertions by Location:\n"
        for coin in coin_summary:
            body += f"- {coin['location_name']} ({coin['device_type']}): ₱{coin['total_amount']}\n"
        
        body += f"\nReport generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Send email
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(email_config['email_username'], email_config['email_password'])
        server.send_message(msg)
        server.quit()
        
        return True
        
    except Exception as e:
        print(f"Error sending daily report: {e}")
        return False

def check_all_voucher_stocks_on_startup(max_retries=5, delay=5):
    print("🔎 Checking voucher stock for all durations on startup...")
    for attempt in range(1, max_retries + 1):
        try:
            duration_mappings = get_duration_mappings()
            print("DEBUG: duration_mappings loaded:", duration_mappings)
            print("DEBUG: About to call get_all_sites()")
            sites = get_all_sites(auto_create=True)
            if not sites:
                print(f"⚠️ No sites found (attempt {attempt}/{max_retries}). Retrying in {delay}s...")
                time.sleep(delay)
                continue
            for site in sites:
                site_id = site['site_id']
                site_name = site['site_name']
                db_path = f"{SITE_DB_PREFIX}{safe_site_name(site_name)}.db"
                if not os.path.exists(db_path):
                    print(f"⚠️ Site DB for {site_name} does not exist. Creating...")
                    create_site_database(site_name)
                for mapping in duration_mappings:
                    duration = mapping['duration']
                    price = mapping['amount']
                    print(f"DEBUG: Checking stock for site '{site_name}' ({site_id}): {duration} min (₱{price})...")
                    generate_vouchers_if_needed(site_id, price, duration)
            break
        except Exception as e:
            print(f"❌ Error during startup voucher stock check: {e}")
            break
    else:
        print("❌ Failed to fetch sites after multiple retries.")

def get_all_voucher_stocks():
    """
    Returns a dict of {site_name: {price: unused_count, ...}, ...}
    for all price tables in all site DBs.
    """
    try:
        site_rows = get_all_sites()
        print(f"DEBUG: site_rows = {site_rows}")
        if not site_rows:
            print("⚠️ No sites found. Returning empty voucher stocks.")
            return {}
        all_stocks = {}
        for row in site_rows:
            site_name = row['site_name']
            print(f"DEBUG: Processing site_name = {site_name}")
            if not site_name:
                print(f"⚠️ No entry found for a site row.")
                continue
            db_path = f"{SITE_DB_PREFIX}{safe_site_name(site_name)}.db"
            print(f"DEBUG: db_path = {db_path}")
            if not os.path.exists(db_path):
                print(f"⚠️ Site DB for {site_name} does not exist.")
                continue
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'price_%'")
            tables = [row['name'] for row in c.fetchall()]
            print(f"DEBUG: price tables for {site_name} = {tables}")
            stocks = {}
            for table in tables:
                price = table.replace('price_', '')
                c.execute(f"SELECT COUNT(*) FROM {table} WHERE used = 0")
                count = c.fetchone()[0]
                print(f"DEBUG: {site_name} - price {price}: {count} unused vouchers")
                stocks[price] = count
            conn.close()
            all_stocks[site_name] = stocks
        print(f"DEBUG: all_stocks = {all_stocks}")
        return all_stocks
    except Exception as e:
        print(f"❌ Error getting all voucher stocks: {e}")
        return {}


if __name__ == '__main__':
    print("Admin routes module loaded")
    print("Available routes:", get_admin_routes_list())