# Intrusion Detection System (IDS)

## Description
This Intrusion Detection System (IDS) is a lightweight Python-based tool that monitors network traffic for suspicious activities. It utilizes Scapy to analyze packets, detect malicious IPs, identify unauthorized access attempts, and flag harmful payloads. The system logs all detected threats and sends email alerts to the administrator, ensuring real-time monitoring and response.

## Features
- **Network Scanning**: Identifies active devices in a given subnet.
- **Packet Sniffing**: Captures and analyzes network packets.
- **Intrusion Detection**: Detects malicious IPs, suspicious port activity, and harmful payloads.
- **Logging & Alerting**: Logs events and sends email alerts when threats are detected.
- **Configurable Suppression Windows**: Avoids duplicate alerts within a set time frame.

## Prerequisites
Ensure you have the following installed on your system:
- Python 3.x
- Scapy (`pip install scapy`)
- `smtplib` for email alerts (included with Python)
- `ipaddress` module (included with Python 3.x)

### Install Dependencies
```bash
pip install scapy
```

## Configuration
The script requires a `configFile.json` for email alert settings. Create a `configFile.json` file with the following structure:

```json
{
    "ALERT_EMAIL": "your_alert_email@example.com",
    "EMAIL_USERNAME": "your_email@gmail.com",
    "EMAIL_PASSWORD": "your_email_password"
}
```

> **Note:** If using Gmail, ensure that "Less Secure Apps" is enabled or use an App Password.

## Usage
### Run the IDS
```bash
python3 ids.py
```

### Parameters
- `SUBNET`: Define the subnet to scan (default: `192.168.1.0/24`).
- `interface`: Set the network interface (default: `wlan0`).
- `LOG_SUPPRESSION_WINDOW`: Time in seconds to suppress duplicate log messages.
- `ALERT_SUPPRESSION_WINDOW`: Time in seconds to suppress duplicate alerts.

## How It Works
1. **Scanning for Active Devices**: The script periodically scans the network for active devices.
2. **Packet Sniffing**: Captures packets on the specified network interface.
3. **Intrusion Detection**:
   - Checks if packets contain known malicious IPs.
   - Detects suspicious port activity (e.g., SSH, RDP ports).
   - Analyzes packet payloads for malicious keywords.
4. **Logging & Alerts**: Logs detected threats and sends an email notification.

## Example Output
```
[INFO] Starting packet sniffer on interface wlan0...
[INFO] ARP packet detected
[ALERT] Malicious IP detected in packet: 192.168.1.50 -> 192.168.1.10
[ALERT] Suspicious port activity: 192.168.1.5:22 -> 192.168.1.8:4321
Alert email sent!
```

## Security Considerations
- Run with administrator/root privileges to capture all network packets.
- Be cautious when handling email credentials (consider using environment variables instead of storing passwords in plaintext).
- This script is for educational and research purposes. Do not use it for unauthorized network monitoring.

## Contributing
Feel free to contribute by opening issues or submitting pull requests!

## License
This project is licensed under the MIT License. See `LICENSE` for details.

## Disclaimer
This tool is for educational and ethical hacking purposes only. The author is not responsible for any misuse of this software.
