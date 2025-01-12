import os
import platform
import socket
import subprocess
from ipaddress import ip_network
from concurrent.futures import ThreadPoolExecutor, as_completed

# Define categorized ports to scan
PORTS_TO_SCAN = {
    "Web Services": [80, 443, 8080, 8000, 8443],
    "SSH and Remote Access": [22, 3389, 23, 5900],
    "Email Services": [25, 110, 143, 465, 587, 993, 995],
    "File Sharing and Transfer": [21, 20, 69, 445, 2049, 139, 548],
    "Database Services": [1433, 1521, 3306, 5432, 27017],
    "Network and System Management": [53, 161, 162, 67, 68, 123, 389, 636],
    "Application Frameworks": [8081, 8181, 5000, 6379, 11211],
    "VPN and Tunneling": [1194, 500, 4500, 1723, 1701],
    "IoT and Embedded Systems": [5555],
    "Other Important Ports": [135, 4444, 31337],
}

### Modular Functions ###
def get_network_details():
    """Retrieve the local IP, gateway, and subnet mask using system commands or environment variables."""
    try:
        # Check for environment variables first (Docker compatibility)
        host_ip = os.getenv("HOST_IP")
        subnet_mask = os.getenv("SUBNET")
        if host_ip and subnet_mask:
            print(f"Using environment variables: HOST_IP={host_ip}, SUBNET={subnet_mask}")
            gateway = os.getenv("GATEWAY", "Unknown")
            return host_ip, gateway, subnet_mask

        # Fallback to system-specific network detection
        system = platform.system().lower()
        if "windows" in system:
            return _get_network_details_windows()
        elif "linux" in system:
            return _get_network_details_linux()
        elif "darwin" in system:  # macOS
            return _get_network_details_macos()
        else:
            raise Exception(f"Unsupported operating system: {system}")
    except Exception as e:
        print(f"Error retrieving network details: {e}")
        return None, None, None

def _get_network_details_windows():
    """Retrieve network details on Windows."""
    try:
        output = subprocess.check_output("ipconfig", text=True).splitlines()
        local_ip, gateway, subnet_mask = None, None, None
        for line in output:
            if "IPv4 Address" in line:
                local_ip = line.split(":")[-1].strip()
            if "Subnet Mask" in line:
                subnet_mask = line.split(":")[-1].strip()
            if "Default Gateway" in line:
                gateway = line.split(":")[-1].strip()
        return local_ip, gateway, subnet_mask
    except Exception as e:
        raise Exception(f"Failed to retrieve network details on Windows: {e}")

def _get_network_details_linux():
    """Retrieve network details on Linux."""
    try:
        # Get the local IP
        local_ip = subprocess.check_output(
            "ip -o -4 addr show | awk '{print $4}' | cut -d/ -f1", 
            shell=True, text=True
        ).splitlines()[0]
        
        # Get the default gateway
        gateway = subprocess.check_output("ip route | grep default", shell=True, text=True).split()[2]
        
        # Set a default subnet mask (can be adjusted for more accuracy)
        subnet_mask = "255.255.255.0"
        
        return local_ip, gateway, subnet_mask
    except Exception as e:
        raise Exception(f"Failed to retrieve network details on Linux: {e}")


def _get_network_details_macos():
    """Retrieve network details on macOS."""
    try:
        # Attempt to fetch the IP address from the default network interface (en0)
        local_ip = subprocess.check_output("ipconfig getifaddr en0", shell=True, text=True).strip()
        
        # If en0 doesn't exist, try fallback interfaces
        if not local_ip:
            local_ip = subprocess.check_output("ipconfig getifaddr en1", shell=True, text=True).strip()
        
        # Retrieve subnet mask and gateway
        subnet_mask = subprocess.check_output("ipconfig getoption en0 subnet_mask", shell=True, text=True).strip()
        gateway = subprocess.check_output("netstat -nr | grep default", shell=True, text=True).split()[1]
        
        return local_ip, gateway, subnet_mask
    except Exception as e:
        raise Exception(f"Failed to retrieve network details on macOS: {e}")


def calculate_network_range(local_ip, subnet_mask):
    """Calculate the range of IP addresses within the subnet."""
    try:
        network = ip_network(f"{local_ip}/{subnet_mask}", strict=False)
        return list(network.hosts())
    except Exception as e:
        print(f"Error calculating network range: {e}")
        return []

def ping_ip(ip):
    """Ping an IP to check if it's active."""
    try:
        cmd = ["ping", "-c", "1", str(ip)] if platform.system().lower() == "linux" else ["ping", "-n", "1", str(ip)]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.returncode == 0
    except Exception as e:
        print(f"Error pinging {ip}: {e}")
        return False

def resolve_hostname(ip):
    """Attempt to resolve the hostname of an IP address."""
    try:
        hostname = socket.gethostbyaddr(str(ip))[0]
        return hostname
    except socket.herror:
        return "Unknown"

def scan_ports(ip, ports):
    """Scan a list of ports on the provided IP."""
    results = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((ip, port))
                status = "Open" if result == 0 else "Closed"
                results.append((port, status))
        except Exception as e:
            results.append((port, f"Error: {e}"))
    return results

def network_scan(network_range, local_ip, gateway):
    """Perform a parallel network scan for active devices."""
    active_ips = []
    print("Scanning the network for active devices...")
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(ping_ip, ip): ip for ip in network_range}
        for future in as_completed(futures):
            ip = futures[future]
            if future.result() and str(ip) not in (local_ip, gateway):
                hostname = resolve_hostname(ip)
                active_ips.append((str(ip), hostname))
                print(f"Active device found: {ip} ({hostname})")
    return active_ips

def display_results(results):
    """Display the results of port scans or active device scans."""
    for idx, (ip, hostname) in enumerate(results, 1):
        print(f"{idx}. {ip} ({hostname})")


### Main Script ###
def main():
    print("Starting Deep Network Explorer...")
    
    # Step 1: Retrieve network details
    local_ip, gateway, subnet_mask = get_network_details()
    if not local_ip or not gateway or not subnet_mask:
        print("Failed to retrieve network details. Exiting.")
        return

    print(f"Local IP: {local_ip}")
    print(f"Gateway: {gateway}")
    print(f"Subnet Mask: {subnet_mask}")

    # Step 2: Calculate the network range
    network_range = calculate_network_range(local_ip, subnet_mask)
    if not network_range:
        print("Failed to calculate network range. Exiting.")
        return

    # Step 3: Perform network scan
    active_ips = network_scan(network_range, local_ip, gateway)
    if not active_ips:
        print("No active devices found. Exiting.")
        return

    print("\nActive Devices Found:")
    display_results(active_ips)

    # Step 4: Prompt for port scanning
    while True:
        choice = input("\nEnter the number of a device to scan ports, or press Enter to exit: ").strip()
        if not choice:
            print("Exiting.")
            break

        if choice.isdigit() and 1 <= int(choice) <= len(active_ips):
            selected_ip = active_ips[int(choice) - 1][0]
            print("\nAvailable Port Categories:")
            for idx, category in enumerate(PORTS_TO_SCAN.keys(), start=1):
                print(f"{idx}. {category}")
            print(f"{len(PORTS_TO_SCAN) + 1}. Scan All Ports")

            port_choice = input("\nSelect a category by number: ").strip()
            if port_choice.isdigit():
                port_choice = int(port_choice)
                categories = list(PORTS_TO_SCAN.keys())
                if 1 <= port_choice <= len(categories):
                    selected_ports = PORTS_TO_SCAN[categories[port_choice - 1]]
                elif port_choice == len(categories) + 1:
                    selected_ports = [port for ports in PORTS_TO_SCAN.values() for port in ports]
                else:
                    print("Invalid category. Returning to main menu.")
                    continue

                # Perform port scan
                port_results = scan_ports(selected_ip, selected_ports)
                print(f"\nPort Scan Results for {selected_ip}:")
                for port, status in port_results:
                    print(f"  Port {port}: {status}")
            else:
                print("Invalid input. Returning to main menu.")
        else:
            print
