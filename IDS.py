from scapy.all import ARP, Ether, sniff, srp, IP, TCP, Raw
from ipaddress import ip_network, ip_address
import smtplib
import time
import logging
import threading
import json

# Logging configure
TEST_LOG ="testLog.txt"
logging.basicConfig(filename = TEST_LOG, level = logging.INFO, format='%(asctime)s:  %(message)s')
log_cache= {}
LOG_SUPPRESSION_WINDOW = 5

with open('configFile.json', 'r') as configFile:
	config = json.load(configFile)
	
# Email Configure
ALERT_EMAIL = config["ALERT_EMAIL"]
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_USERNAME = config["EMAIL_USERNAME"]
EMAIL_PASSWORD = config["EMAIL_PASSWORD"]
alert_cache ={}
ALERT_SUPPRESSION_WINDOW = 600


SUBNET  = "192.168.1.0/24"

active_ips = []

# Sample intrusions
SIGNATURES = {
	"malicious_ips": ["192.168.1.50", "203.0.113.5"], 
	"ports": [22, 3389],
	"payload_keywords": [b"malware", b"exploit", b"attack"]
}

# Log Suppression

def logOnce(message, level= "info"):
	global log_cache
	current_time = time.time()
	
	log_cache = {msg: ts for msg, ts in log_cache.items() if current_time  - ts < LOG_SUPPRESSION_WINDOW}
	
	if message in log_cache:
		print(f"[INFO] Log suppressed: {message}")
		return
	log_cache[message] = current_time
	if level == "warning":
		logging.warning(message)
	else:
		logging.info(message)
	
	print(message)

# Email alert
def sendEmailAlert(message):
	global alert_cache
	current_time = time.time()

	# Remove expired alerts from cache
	alert_cache = {msg: ts for msg, ts in alert_cache.items() if current_time - ts < ALERT_SUPPRESSION_WINDOW}

	# Suppress duplicate alerts
	if message in alert_cache:
		print(f"[INFO] Alert suppressed: {message}")
		return
	try:
		server= smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
		server.starttls()
		server.login(EMAIL_USERNAME, EMAIL_PASSWORD)

		subject = "Intrusion Alert"
		email_message = f"Subject: {subject}\n\n{message}"

		server.sendmail(EMAIL_USERNAME, ALERT_EMAIL, email_message)
		server.quit()
		print("Alert email sent!")

		alert_cache[message] = current_time	

	except Exception as e:
		print(f"Error sending email:{e}")
		
		
# Find active IP's
def discoverActiveIPs(subnet = SUBNET):
	print(f"Scanning for active devices in {subnet}...")
	active_ipsLOCAL= []
	try:
		arp = ARP(pdst= subnet)
		ether = Ether(dst = "ff:ff:ff:ff:ff:ff")
		packet = ether / arp
		
		result = srp(packet, timeout = 2, verbose = False)[0]	
		
		for sent, received in result:
			active_ipsLOCAL.append(received.psrc)
			
		print(f"Active devices found: {active_ipsLOCAL}")
		
	except Exception as e:
		print(f"Error in scanning for active devices: {e}")
		
	return active_ipsLOCAL
	

# Analyze Packets

def analyzePacket(packet):
	try:
		if packet.haslayer(ARP):
			logging.info("Detected ARP packet")
			logOnce("[INFO] ARP packet detected")
						
		if packet.haslayer(IP):
			srcIP = packet[IP].src
			dstIP = packet[IP].dst
			
			if srcIP in SIGNATURES["malicious_ips"] or dstIP in SIGNATURES["malicious_ips"]:
				message = f"[ALERT] Malicious IP detected in packet: {srcIP}->{dstIP}"
				logging.warning(message)
				logOnce(message)
				sendEmailAlert(message)
				
			if packet.haslayer(TCP):
				srcPort = packet[TCP].sport
				dstPort = packet[TCP].dport
				
				if srcPort in SIGNATURES["ports"] or dstPort in SIGNATURES["ports"]:
					message = f"[ALERT] Suspicious port activity: {srcIP}:{srcPort} -> {dstIP}:{dstPort}"
					logging.warning(message)
					logOnce(message)
					sendEmailAlert(message)
						
		if packet.haslayer(Raw):
			payload = packet[Raw].load
			for keyword in SIGNATURES["payload_keywords"]:
				if keyword in payload:
					message = f"[ALERT] Suspicious payload detected from {srcIP} to {dstIP}: {payload}"
					logging.warning(message)
					logOnce(message)
					sendEmailAlert(message)
	
	except Exception as e:
		print(f"[ERROR] Error analyzing packet: {e}")
		

# Scan periodically and update active ip's	
def periodicScan(interval = 60):
	global active_ips
	while True:
		active_ips = discoverActiveIPs()
		print(f"[INFO] Updated active devices: {active_ips}")
		time.sleep(interval)
	
# Sniffing Packets
def startSniffer(interface):
	print(f"[INFO] Starting packet sniffer on interface {interface}...")
	sniff(iface = interface, prn= analyzePacket, store = False)


if __name__ == "__main__":
	print("Starting IDS...")
	interface = "wlan0"
	active_ips = discoverActiveIPs()
	
	threading.Thread(target = periodicScan, args= (60,), daemon = True).start()
	
	startSniffer(interface)
	
	
	
	
	
	
	
	
	
	
	
	
	
	
