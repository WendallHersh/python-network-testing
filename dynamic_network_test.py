import os
import socket
from ping3 import ping
import netifaces as ni

# Helper Functions
def get_local_ip():
    """
    Get the local IP address of the computer.
    """
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        return local_ip
    except Exception as e:
        print(f"Error getting local IP: {e}")
        return None


def get_router_ip():
    """
    Get the router's IP address by retrieving the gateway IP.
    """
    try:
        gateways = ni.gateways()
        router_ip = gateways['default'][ni.AF_INET][0]
        return router_ip
    except Exception as e:
        print(f"Error getting router IP: {e}")
        return None


def test_ping(ip):
    """
    Test if a device is reachable by sending a ping.
    """
    try:
        response = ping(ip, timeout=2)
        if response:
            print(f"✅ Ping successful for {ip}. Response time: {response:.2f} ms")
        else:
            print(f"❌ Ping failed for {ip}. No response.")
    except Exception as e:
        print(f"❌ Ping error for {ip}: {e}")



def test_ports(ip, ports):
    """
    Test if specified ports are open on a device.
    """
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)  # Timeout after 2 seconds
                result = sock.connect_ex((ip, port))
                if result == 0:
                    print(f"✅ Port {port} is open on {ip}")
                else:
                    print(f"❌ Port {port} is closed on {ip}")
        except Exception as e:
            print(f"❌ Error checking port {port} on {ip}: {e}")


if __name__ == "__main__":
    print("🏠 Starting Home Network Test...")

    # Dynamically get the local and router IPs
    local_ip = get_local_ip()
    router_ip = get_router_ip()

    if not local_ip or not router_ip:
        print("❌ Could not retrieve local or router IP. Exiting.")
        exit(1)

    # Configuration for the test
    devices = {
        "Router": router_ip,
        "This Device (Local)": local_ip
    }
    ports_to_check = [80, 443, 22]  # Common ports: HTTP, HTTPS, SSH

    # Test each device in the network
    for device_name, ip in devices.items():
        print(f"\nTesting {device_name} ({ip})...")
        test_ping(ip)
        test_ports(ip, ports_to_check)

    print("\n🏁 Network test completed!")
