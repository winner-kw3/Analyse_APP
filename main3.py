import pyshark
import json
import time
import requests
from dotenv import load_dotenv
import os
from collections import defaultdict

load_dotenv()

# Configuration

PCAP_FILE = 'ex4.pcap'
OUTPUT_JSON = 'main.json'
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
VT_API_URL = 'https://www.virustotal.com/api/v3/ip_addresses/'
REQUEST_DELAY = 15  # Respect de la limite de 4 requêtes/minute
THRESHOLD = 5  # Seuil d'activité suspecte ajusté
PORTS_SUSPECTS = {22, 3389, 445, 80, 443}  # Ports souvent liés à des attaques

# Fonction d'extraction des IPs et analyse des comportements suspects
def extract_suspicious_ips(pcap_file):
    with pyshark.FileCapture(pcap_file, display_filter='ip', use_json=True) as cap:
        ip_counter = defaultdict(int)
        ip_ports = defaultdict(set)
        external_ips = defaultdict(int)
        local_ips = defaultdict(int)
        ip_packets = defaultdict(int)
        ip_targets = defaultdict(set)
        ip_protocols = defaultdict(set)
        
        for packet in cap:
            try:
                if hasattr(packet, 'ip'):
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    ip_counter[src_ip] += 1
                    ip_counter[dst_ip] += 1
                    ip_packets[src_ip] += 1
                    ip_packets[dst_ip] += 1
                    ip_targets[src_ip].add(dst_ip)
                    
                    # Vérifier les ports utilisés
                    if hasattr(packet, 'tcp'):
                        ip_ports[src_ip].add(int(packet.tcp.dstport))
                        ip_ports[dst_ip].add(int(packet.tcp.srcport))
                    
                    # Vérifier les protocoles utilisés
                    ip_protocols[src_ip].add(packet.highest_layer)
                    ip_protocols[dst_ip].add(packet.highest_layer)
                    
                    # Détecter les IPs internes et externes
                    if src_ip.startswith("192.168.") or src_ip.startswith("10.") or src_ip.startswith("172.16."):
                        local_ips[src_ip] += 1
                    else:
                        external_ips[src_ip] += 1
            except AttributeError:
                continue
    
    suspect_ips = []
    for ip, count in ip_counter.items():
        if count > THRESHOLD:
            suspect_ips.append(ip)
        elif external_ips[ip] > THRESHOLD // 2:
            suspect_ips.append(ip)
        elif ip_ports[ip] & PORTS_SUSPECTS:
            suspect_ips.append(ip)
    
    return suspect_ips, ip_packets, ip_targets, ip_protocols, external_ips, local_ips, ip_ports

# Vérification des IPs via VirusTotal
def check_ip_virustotal(ip):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(VT_API_URL + ip, headers=headers)
    
    if response.status_code == 200:
        return response.json().get("data", {}).get("attributes", {})
    else:
        print(f"Erreur API pour {ip}: {response.status_code} - {response.text}")
    return None

# Analyse des logs
suspect_ips, ip_packets, ip_targets, ip_protocols, external_ips, local_ips, ip_ports = extract_suspicious_ips(PCAP_FILE)
analysis_results = []

for ip in suspect_ips[:500]:  # Respect de la limite de 500 requêtes/jour
    print(f"Analyse de l'IP : {ip}")
    ip_data = check_ip_virustotal(ip)
    
    classification = "Securisee"
    if ip in external_ips and external_ips[ip] > THRESHOLD // 2:
        classification = "Suspecte"
    if ip in ip_ports and ip_ports[ip] & PORTS_SUSPECTS:
        classification = "Dangereuse"
    
    result = {
        "ip": ip,
        "last_analysis_stats": ip_data.get("last_analysis_stats", {}) if ip_data else {},
        "reputation": ip_data.get("reputation", "N/A") if ip_data else "N/A",
        "last_analysis_date": ip_data.get("last_analysis_date", "N/A") if ip_data else "N/A",
        "country": ip_data.get("country", "Unknown") if ip_data else "Unknown",
        "as_owner": ip_data.get("as_owner", "Unknown") if ip_data else "Unknown",
        "tags": ip_data.get("tags", []) if ip_data else [],
        "total_packets": ip_packets.get(ip, 0),
        "targeted_machines": list(ip_targets.get(ip, [])),
        "protocols_used": list(ip_protocols.get(ip, [])),
        "connection_type": "Externe" if ip not in local_ips else "Interne",
        "classification": classification,
        "attacks": []  # Ajout des attaques si un pattern est détecté
    }
    analysis_results.append(result)
    
    time.sleep(REQUEST_DELAY)

# Génération du rapport JSON
report = {
    "total_ips_analyzed": len(suspect_ips),
    "suspect_ips": suspect_ips,
    "analysis_results": analysis_results
}

with open(OUTPUT_JSON, 'w') as f:
    json.dump(report, f, indent=4)

print("Analyse terminée. Rapport généré avec succès.")