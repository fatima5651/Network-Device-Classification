import nmap
import pandas as pd
import json
from tabulate import tabulate

# MAC vendor prefixes for simple device identification
MAC_VENDORS = {
    "Apple": ["00:17:F2", "AC:BC:32", "F0:18:98"],
    "Samsung": ["A4:5E:60", "B8:27:EB"],
    "Cisco": ["00:1B:54", "00:1E:0B"],
}

# Guess OS based on TTL values
def guess_os(ttl):
    if ttl >= 128:
        return "Windows"
    elif ttl >= 64:
        return "Linux/Unix"
    elif ttl >= 255:
        return "Network Device/Router"
    else:
        return "Unknown"

# Guess device type using MAC, open ports, OS, and optionally service banner
def guess_device_type(mac, open_ports, os_name, banner=""):
    mac_prefix = mac.upper()[:8] if mac else ""
    for vendor, prefixes in MAC_VENDORS.items():
        if any(mac_prefix.startswith(p) for p in prefixes):
            if vendor == "Apple":
                return "Mobile" if os_name.startswith("iOS") or "iPhone" in banner else "Laptop"
            if vendor == "Samsung":
                return "Mobile"
            if vendor == "Cisco":
                return "Router/Switch"
    # Port-based heuristics
    if 22 in open_ports or 3389 in open_ports or 445 in open_ports:
        return "Laptop" if "Windows" in os_name else "Server"
    if 80 in open_ports or 443 in open_ports:
        return "Server"
    return "Unknown"

# Assign role based on device type
def assign_role(device_type):
    if device_type == "Laptop":
        return "Personal Laptop"
    if device_type == "Server":
        return "Server"
    if device_type == "Mobile":
        return "Mobile Device"
    if device_type in ["Router/Switch", "Gateway", "Router"]:
        return "Network Device"
    return "Unknown"

# Assign criticality score based on device type, open ports, and external exposure
def criticality_score(device_type, open_ports, public=False):
    score = 1  # default low-risk
    if device_type in ["Server", "Laptop"]:
        score += 2  # higher risk for servers and laptops
    if public:
        score += 1  # increase score if device is externally exposed
    # Increase score for critical ports
    if any(p in open_ports for p in [22, 3389, 443, 3306, 5432]):
        score += 1
    return min(score, 5)  # max score is 5

# Scan the network using nmap
def scan_network(network_range, default_gateway=None):
    nm = nmap.PortScanner()
    # Scan with SYN, OS detection, and service version detection
    nm.scan(hosts=network_range, arguments='-sS -sV -O ')
    devices = []
    for host in nm.all_hosts():
        # OS detection
        os_guess = "Unknown"
        try:
            os_guess = nm[host]['osmatch'][0]['name'] if nm[host].get('osmatch') else guess_os(nm[host]['status'].get('ttl', 64))
        except:
            os_guess = guess_os(64)

        # Collect open TCP ports
        open_ports = [int(p) for p in nm[host]['tcp']] if 'tcp' in nm[host] else []

        # MAC address if available
        mac = nm[host]['addresses'].get('mac') if 'addresses' in nm[host] else None

        banner = ""  # could integrate service banners here

        # Default device type and role
        device_type = guess_device_type(mac, open_ports, os_guess, banner)
        role = assign_role(device_type)
        public = False

        # Override for default gateway to mark it as Router
        if default_gateway and host == default_gateway:
            device_type = "Router"
            role = "Network Device"

        # Compute criticality
        crit_score = criticality_score(device_type, open_ports, public)

        # Append device info
        devices.append({
            "IP": host,
            "OS": os_guess,
            "Device Type": device_type,
            "Role": role,
            "Criticality Score": crit_score
        })
    return devices

# Process devices from JSON file
def process_json(json_path):
    with open(json_path, 'r') as f:
        data = json.load(f)
    devices = []
    for item in data:
        os_name = guess_os(item.get('ttl', 64))
        device_type = guess_device_type(item.get('mac'), item.get('open_ports', []), os_name, item.get('banner', ""))
        role = assign_role(device_type)
        crit_score = criticality_score(device_type, item.get('open_ports', []), item.get('public', False))
        devices.append({
            "IP": item.get('ip'),
            "OS": os_name,
            "Device Type": device_type,
            "Role": role,
            "Criticality Score": crit_score
        })
    return devices

# Main program
def main():
    print("Network Device Classification Tool")
    print("Choose a mode:")
    print("1. Scan your local network (requires python-nmap)")
    print("2. Use simulated network data (JSON file)")
    choice = input("Enter 1 or 2: ")

    if choice == "1":
        network_range = input("Enter network range (e.g., 192.168.1.0/24): ")
        default_gateway = input("Enter default gateway IP (or leave blank if unknown): ").strip() or None
        print("Scanning network, this may take a few minutes...")
        devices = scan_network(network_range, default_gateway)
    elif choice == "2":
        json_path = input("Enter path to JSON file: ")
        devices = process_json(json_path)
    else:
        print("Invalid choice. Exiting.")
        return

    # Display results
    df = pd.DataFrame(devices)
    print("\nClassified Devices:")
    print(tabulate(df, headers='keys', tablefmt='grid'))

    # Save to CSV
    df.to_csv("network_classification.csv", index=False)
    print("\nSaved results to network_classification.csv")

if __name__ == "__main__":
    main()

