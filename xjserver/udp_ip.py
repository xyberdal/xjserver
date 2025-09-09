import esp32_udp_listener
from omada_api import periodic_controller_ip_scan

if __name__ == "__main__":
    print("🚀 Starting UDP listener and running controller IP scan once...")
    periodic_controller_ip_scan()  # Run once
    esp32_udp_listener.udp_listener()  # This should block and run forever