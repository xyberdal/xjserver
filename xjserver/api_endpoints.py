import psutil
import socket
import time
import os
import subprocess
from datetime import datetime, timedelta
from flask import app, request, jsonify, session

# Import database utilities
from database import (
    get_db, get_all_sites,
    get_database_stats, get_adopted_esp32s,
    create_site_database
)

def create_api_routes(app, discovered_esp32s):
    """Create all API endpoints"""
    
    # ===== SYSTEM STATUS API =====
    
    @app.route('/api/ping')
    def api_ping():
        """System health check"""
        return jsonify({
            'status': 'ok',
            'timestamp': datetime.now().isoformat(),
            'server_time': time.time()
        })
    
    @app.route('/api/stats')
    def api_stats():
        try:
            stats = get_database_stats()  # All DB stats
    
            # Add ESP32 online count (not in DB)
            stats['devices_online'] = len([info for info in (discovered_esp32s or {}).values() if info.get('is_online', False)])
    
            # Add live Orange Pi stats
            stats['cpu'] = psutil.cpu_percent(interval=0.5)
            stats['ram'] = psutil.virtual_memory().percent
            stats['disk'] = psutil.disk_usage('/').percent
    
            # Uptime
            try:
                uptime_seconds = float(os.popen('cat /proc/uptime').read().split()[0])
                stats['uptime'] = str(timedelta(seconds=int(uptime_seconds)))
            except Exception:
                stats['uptime'] = "N/A"
    
            # IP address
            try:
                # This gets the primary local IP address (not 127.0.0.1)
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(0)
                try:
                    # Doesn't have to be reachable
                    s.connect(('10.255.255.255', 1))
                    stats['ip'] = s.getsockname()[0]
                except Exception:
                    stats['ip'] = "N/A"
                finally:
                    s.close()
            except Exception:
                stats['ip'] = "N/A"
            # ...existing code...
    
            # Add timestamp
            stats['timestamp'] = datetime.now().isoformat()
    
            return jsonify(stats)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    # ===== PULSE MAPPING API =====
    
    @app.route('/api/pulse/mappings')
    def api_get_pulse_mappings():
        """Get all pulse mappings"""
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute('SELECT pulse_count, amount, created_at FROM pulse_mappings ORDER BY pulse_count')
            
            mappings = []
            for row in c.fetchall():
                mappings.append({
                    'pulse_count': row['pulse_count'],
                    'amount': row['amount'],
                    'created_at': row['created_at']
                })
            
            conn.close()
            return jsonify({'mappings': mappings})
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/pulse/mappings', methods=['POST'])
    def api_save_pulse_mapping():
        """Save pulse mapping"""
        try:
            data = request.get_json()
            pulse_count = data.get('pulse_count')
            amount = data.get('amount')
            
            if pulse_count is None or amount is None:
                return jsonify({'error': 'pulse_count and amount required'}), 400
            
            if pulse_count <= 0 or amount <= 0:
                return jsonify({'error': 'pulse_count and amount must be positive'}), 400
            
            conn = get_db()
            c = conn.cursor()
            
            # Insert or update mapping
            c.execute('''INSERT OR REPLACE INTO pulse_mappings 
                         (pulse_count, amount, created_at)
                         VALUES (?, ?, ?)''',
                     (pulse_count, amount, datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            
            return jsonify({
                'pulse_count': pulse_count,
                'amount': amount,
                'message': 'Mapping saved successfully'
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/pulse/mappings/<int:pulse_count>', methods=['DELETE'])
    def api_delete_pulse_mapping(pulse_count):
        """Delete pulse mapping"""
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute('DELETE FROM pulse_mappings WHERE pulse_count = ?', (pulse_count,))
            
            if c.rowcount == 0:
                conn.close()
                return jsonify({'error': 'Mapping not found'}), 404
            
            conn.commit()
            conn.close()
            
            return jsonify({'message': f'Mapping for {pulse_count} pulses deleted'})
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    # ===== ESP32 MANAGEMENT API =====
    @app.route('/api/esp32/devices')
    def api_esp32_devices():
        """Get ESP32 device status"""
        try:
            devices = get_adopted_esp32s()
            device_status = []
            
            for device in devices:
                # Check if device is online
                is_online = any(
                    info.get("device_type") == device['device_type'] and 
                    info.get("location_name") == device['location_name']
                    for info in discovered_esp32s.values()
                )
                
                device_status.append({
                    'device_type': device['device_type'],
                    'location_name': device['location_name'],
                    'site_id': device['site_id'],
                    'mac_address': device['mac_address'],
                    'is_online': is_online,
                    'last_seen': None  # Could be added to database
                })
            
            return jsonify({'devices': device_status})
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
       
    # ===== VOUCHER STATUS API =====
    
    @app.route('/api/vouchers/status')
    def api_voucher_status():
        """Get voucher counts for all sites and prices"""
        try:
            sites = get_all_sites()
            voucher_status = []
            
            for site in sites:
                site_id = site['site_id']
                
                # Get all uploaded prices for this site
                conn = get_db()
                c = conn.cursor()
                c.execute('SELECT DISTINCT price FROM voucher_uploads WHERE site_id = ?', (site_id,))
                prices = c.fetchall()
                conn.close()
                
                site_info = {
                    'site_id': site_id,
                    'site_name': site['site_name'],
                    'prices': []
                }
                
                for price_row in prices:
                    price = price_row['price']
                    count = get_voucher_count(site_id, price)
                    
                    site_info['prices'].append({
                        'price': price,
                        'available_vouchers': count,
                        'needs_generation': count < 10
                    })
                
                voucher_status.append(site_info)
            
            return jsonify({'voucher_status': voucher_status})
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    # Add these new API endpoints after the existing ones:
    
    @app.route('/api/voucher-stock-summary')
    def api_voucher_stock_summary():
        """Get voucher stock summary from unified database"""
        try:
            summary = database.get_voucher_stock_summary()
            return jsonify(summary)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/voucher-usage-by-location')
    def api_voucher_usage_by_location():
        """Get voucher usage statistics by ESP32 location"""
        try:
            usage = database.get_voucher_usage_by_location()
            return jsonify(usage)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/voucher-stock/<int:duration>')
    def api_voucher_stock_by_duration(duration):
        """Get available voucher count for specific duration"""
        try:
            count = database.get_voucher_stock_by_duration(duration)
            return jsonify({'duration': duration, 'available_count': count})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    # ===== DURATION MAPPING API =====

    @app.route('/api/duration/mappings/save', methods=['POST'])
    def api_save_duration_mappings():
        """Save all duration mappings (bulk replace)"""
        try:
            data = request.get_json()
            mappings = data.get('mappings', [])
            if not isinstance(mappings, list):
                return jsonify({'error': 'mappings must be a list'}), 400
    
            conn = get_db()
            c = conn.cursor()
            # Clear old mappings
            c.execute('DELETE FROM duration_mappings')
            # Insert new mappings
            for m in mappings:
                c.execute('''INSERT INTO duration_mappings (amount, duration, description, created_at)
                             VALUES (?, ?, ?, ?)''',
                          (m['amount'], m['duration'], m.get('description', ''), datetime.now().isoformat()))
            conn.commit()
            conn.close()
    
            # --- Update all site databases to reflect new mappings ---
            sites = get_all_sites()
            for site in sites:
                create_site_database(site['site_name'])
    
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    @app.route('/api/duration/mappings/current')
    def api_get_duration_mappings():
        """Get all current duration mappings"""
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute('SELECT id, amount, duration, description, created_at FROM duration_mappings ORDER BY amount')
            mappings = [dict(row) for row in c.fetchall()]
            conn.close()
            return jsonify({'mappings': mappings})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/duration/mappings/<int:mapping_id>', methods=['DELETE'])
    def api_delete_duration_mapping(mapping_id):
        """Delete a duration mapping by ID"""
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute('DELETE FROM duration_mappings WHERE id = ?', (mapping_id,))
            conn.commit()
            conn.close()

             # --- Update all site databases to reflect new mappings ---
            sites = get_all_sites()
            for site in sites:
                create_site_database(site['site_name'])
            
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    # ===== DEVICE DELETE API =====

    @app.route('/api/devices/delete', methods=['POST'])
    def api_delete_device():
        data = request.get_json()
        location_name = data.get('id')
        if not location_name:
            return jsonify({'success': False, 'error': 'Missing ID'}), 400
    
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute('DELETE FROM esp32_devices WHERE id = ?', (location_name,))
            conn.commit()
            conn.close()
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    # ===== EMAIL TEST API =====
    
    # ===== SYSTEM CONTROL API =====
    
    @app.route('/api/system/restart', methods=['POST'])
    def api_system_restart():
        """Restart XJServer (requires admin privileges)"""
        try:
            # Check if user is admin
            if not session.get('logged_in'):
                return jsonify({'error': 'Authentication required'}), 401
            
            # Schedule restart
            subprocess.Popen(['python3', '-c', '''
import time
import os
import signal
time.sleep(2)
os.kill({}, signal.SIGTERM)
'''.format(os.getpid())], cwd=os.path.dirname(os.path.abspath(__file__)))
            
            return jsonify({'message': 'Server restart scheduled'})
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    # ===== DISCOVERY API =====
    
    @app.route('/api/discovery/esp32')
    def api_discovery_esp32():
        """Get discovered ESP32 devices"""
        try:
            devices = []
            for ip, info in discovered_esp32s.items():
                devices.append({
                    'ip': ip,
                    'device_type': info.get('device_type'),
                    'location_name': info.get('location_name'),
                    'mac_address': info.get('mac_address'),
                    'is_online': info.get('is_online', False),
                    'last_seen': info.get('last_seen'),
                    'rssi': info.get('rssi'),
                    'uptime': info.get('uptime')
                })
            
            return jsonify({
                'discovered_devices': devices,
                'total_discovered': len(devices),
                'online_count': len([d for d in devices if d['is_online']])
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    # ===== HEALTH CHECK API =====
    
    @app.route('/api/health')
    def api_health():
        """Comprehensive system health check"""
        try:
            health_status = {
                'status': 'healthy',
                'timestamp': datetime.now().isoformat(),
                'components': {}
            }
            
            # Database health
            try:
                conn = get_db()
                c = conn.cursor()
                c.execute('SELECT 1')
                conn.close()
                health_status['components']['database'] = 'healthy'
            except Exception as e:
                health_status['components']['database'] = f'unhealthy: {str(e)}'
                health_status['status'] = 'degraded'
            
            # ESP32 connectivity
            online_devices = len([info for info in discovered_esp32s.values() if info.get('is_online', False)])
            total_devices = len(discovered_esp32s)
            
            if total_devices > 0:
                device_health = 'healthy' if online_devices == total_devices else 'partial'
                if online_devices == 0:
                    device_health = 'unhealthy'
                    health_status['status'] = 'degraded'
            else:
                device_health = 'no_devices'
            
            health_status['components']['esp32_devices'] = {
                'status': device_health,
                'online': online_devices,
                'total': total_devices
            }
            
            
            return jsonify(health_status)
            
        except Exception as e:
            return jsonify({
                'status': 'unhealthy',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }), 500

def get_api_routes_list():
    """Get list of API routes"""
    return [
        'api_ping', 'api_stats',
        'api_get_pulse_mappings', 'api_save_pulse_mapping', 'api_delete_pulse_mapping',
        'api_esp32_sessions', 'api_esp32_cleanup', 'api_esp32_devices',
        'api_adoption_status', 
        'api_voucher_status', 'api_email_test', 'api_system_restart',
        'api_discovery_esp32', 'api_health',
        'api_voucher_stock_summary', 'api_voucher_usage_by_location', 'api_voucher_stock_by_duration',
        'api_save_duration_mappings', 'api_get_duration_mappings', 'api_delete_duration_mapping',
        'api_devices_ping', 'api_devices_ping_post'
    ]

if __name__ == '__main__':
    print("API endpoints module loaded")
    print("Available endpoints:", get_api_routes_list())