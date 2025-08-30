# Network Device Classification Tool

Device Classification Tool that can analyze network data and highlight the most critical assets. The goal is to simulate how SOC analysts fingerprint devices and assign risk scores.

## Features

- **OS Fingerprinting**: Identifies operating systems using TTL values, TCP window sizes, and service banners
- **Device Type Classification**: Categorizes devices (e.g., iPhone, Windows PC, Smart TV).
- **Role Assignment**: Determines device roles (e.g., Work Laptop, Mobile Device)
- **Criticality Scoring**: Assigns risk scores (1-5) based on Sensitivity of services, Device type, and External exposure

## Installation

```bash
git clone https://github.com/fatima5651/Network-Device-Classification.git
cd Network-Device-Classification
```
