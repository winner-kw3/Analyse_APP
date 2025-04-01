import requests

# URL de l'API
url = "http://93.127.203.48:5000/pcap/latest"

# requête GET pour récupérer le fichier PCAP
response = requests.get(url)


if response.status_code == 200:
    with open("logs.pcap", "wb") as f:
        f.write(response.content)
    print("Fichier PCAP récupéré avec succès !")
else:
    print(f"Erreur lors de la récupération des logs : {response.status_code}")
