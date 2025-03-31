import pyshark
import requests
import json

# Clé API VirusTotal (remplace par ta propre clé API)
VIRUSTOTAL_API_KEY = "e86ab84008ab969e3153c214e3d268e07e36a428d71bac786c36b4316e3af819"
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

# Fonction pour analyser le PCAP et extraire les IP et protocoles
def extract_details_from_pcap(pcap_file):
    capture = pyshark.FileCapture(pcap_file)
    ip_details = {}
    
    for packet in capture:
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            protocol = packet.highest_layer if hasattr(packet, 'highest_layer') else "Unknown"
            
            if src_ip not in ip_details:
                ip_details[src_ip] = {"protocols": set(), "connections": set()}
            if dst_ip not in ip_details:
                ip_details[dst_ip] = {"protocols": set(), "connections": set()}
                
            ip_details[src_ip]["protocols"].add(protocol)
            ip_details[src_ip]["connections"].add(dst_ip)
            ip_details[dst_ip]["protocols"].add(protocol)
            ip_details[dst_ip]["connections"].add(src_ip)
    
    capture.close()
    
    for ip in ip_details:
        ip_details[ip]["protocols"] = list(ip_details[ip]["protocols"])
        ip_details[ip]["connections"] = list(ip_details[ip]["connections"])
    
    return ip_details

# Fonction pour interroger VirusTotal
def check_ip_virustotal(ip):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(VT_URL + ip, headers=headers)
    if response.status_code == 200:
        data = response.json()
        malicious = data['data']['attributes']['last_analysis_stats']['malicious']
        return malicious
    return None

# Exécution
def main():
    pcap_file = "ex4.pcap"  # Remplace par ton fichier
    print("Analyse du fichier PCAP...")
    ip_details = extract_details_from_pcap(pcap_file)
    
    results = {}
    print("Résultat de l'analyse des IPs :")
    for ip, details in ip_details.items():
        result = check_ip_virustotal(ip)
        results[ip] = {
            "malicious": result if result is not None else "Pas d'information",
            "protocols": details["protocols"],
            "connections": details["connections"]
        }
        print(f"{ip} -> {results[ip]['malicious']} moteurs le considèrent comme malveillant")
    
    # Sauvegarde des résultats dans un fichier JSON
    with open("analyse_detaillee.json", "w") as json_file:
        json.dump(results, json_file, indent=4)
    print("Les résultats détaillés ont été enregistrés dans 'analyse_detaillee.json'")

if __name__ == "__main__":
    main()