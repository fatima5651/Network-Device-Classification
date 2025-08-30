# Network Device Classification Tool

Device Classification Tool that analyzes network data and highlights the most critical assets. The goal is to simulate how SOC analysts fingerprint devices and assign risk scores.

## Objective
Analyze network data to fingerprint devices and highlight the most important security issues. Simulate how SOC analysts classify assets and assign criticality based on risk.

## Features

- **OS Fingerprinting**: Identifies operating systems using TTL values, TCP window sizes, and service banners.  
- **Device Type Classification**: Categorizes devices (e.g., iPhone, Windows PC, Smart TV).  
- **Role Assignment**: Determines device roles (e.g., Work Laptop, Mobile Device, Server).  
- **Criticality Scoring**: Assigns risk scores (1–5) based on sensitivity of services, device type, and external exposure.  
- **Interactive Modes**:  
    **1.** Scan your own network using Nmap (requires `python-nmap`).  
    **2.** Use simulated network data from a JSON file.

## Expected Outcome
A table classifying devices with OS, type, role, and criticality score. The output is saved as `network_classification.csv` and displayed in the console.

## Installation
Clone the repository and install the required dependencies:
```bash
git clone https://github.com/fatima5651/Network-Device-Classification.git
cd Network-Device-Classification
pip install -r requirements.txt
```
## Usage
```bash
python network_device_classification.py
```

**Choose a mode** when prompted:  
    **1**. Scan your local network (requires `python-nmap`)  
    **2**. Use simulated network data (JSON file)
Follow the prompts to provide necessary inputs (e.g., JSON file path).

### Output
The tool outputs:
- A **classified device table** in the console (nicely formatted using `tabulate`)  
- A **CSV file** named `network_classification.csv` in the current folder

### Sample JSON Format
Here’s an example of how your simulated network data should look:

```json
[
  {
    "ip": "192.168.1.10",
    "ttl": 128,
    "window_size": 8192,
    "banner": "Microsoft Windows 10",
    "open_ports": [80, 443],
    "public": false
  },
  {
    "ip": "192.168.1.15",
    "ttl": 64,
    "window_size": 65535,
    "banner": "Apple iPhone iOS 17",
    "open_ports": [22, 443],
    "public": false
  },
  {
    "ip": "192.168.1.20",
    "ttl": 255,
    "window_size": 5840,
    "banner": "Linux Ubuntu 22.04",
    "open_ports": [22, 3306],
    "public": true
  }
]
```
**Note:** Place your JSON file in the same folder as the script or provide the full path when prompted.
### Example Output
| IP           | OS                   | Device Type | Role          | Criticality Score |
|--------------|----------------------|-------------|---------------|-------------------|
| 192.168.1.10 | Microsoft Windows 10 | Windows PC  | Work Laptop   | 3                 |
| 192.168.1.15 | Apple iPhone iOS 17  | Mobile      | Mobile Device | 2                 |
| 192.168.1.20 | Linux Ubuntu 22.04   | Server      | Server        | 5                 |

### Sample JSON Format Here’s an example of how your simulated network data should look:
json
[
  {
    "ip": "192.168.1.10",
    "ttl": 128,
    "window_size": 8192,
    "banner": "Microsoft Windows 10",
    "open_ports": [80, 443],
    "public": false
  },
  {
    "ip": "192.168.1.15",
    "ttl": 64,
    "window_size": 65535,
    "banner": "Apple iPhone iOS 17",
    "open_ports": [22, 443],
    "public": false
  },
  {
    "ip": "192.168.1.20",
    "ttl": 255,
    "window_size": 5840,
    "banner": "Linux Ubuntu 22.04",
    "open_ports": [22, 3306],
    "public": true
  }
]

