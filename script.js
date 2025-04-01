const data = {
    "total_ips_analyzed": 11,
    "suspect_ips": [
        "172.17.8.109",
        "172.17.8.255",
        "172.17.8.2",
        "224.0.0.22",
        "224.0.0.252",
        "23.50.224.8",
        "239.255.255.250",
        "91.121.30.169",
        "192.241.220.183",
        "204.2.193.184",
        "216.239.94.252"
    ],
    "analysis_results": [
        {
            "ip": "172.17.8.109",
            "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "undetected": 31,
                "harmless": 63,
                "timeout": 0
            },
            "reputation": 0,
            "last_analysis_date": 1743422206,
            "country": "Unknown",
            "as_owner": "Unknown",
            "tags": [
                "private"
            ],
            "total_packets": 3690,
            "targeted_machines": [
                "172.17.8.255",
                "91.121.30.169",
                "23.50.224.8",
                "239.255.255.250",
                "216.239.94.252",
                "255.255.255.255",
                "224.0.0.22",
                "192.241.220.183",
                "204.2.193.184",
                "172.17.8.2",
                "224.0.0.252"
            ],
            "protocols_used": [
                "TLS",
                "RPC_NETLOGON",
                "LSARPC",
                "TCP",
                "IGMP",
                "SMB",
                "EPM",
                "KERBEROS",
                "SMB2",
                "LDAP",
                "SSDP",
                "DCERPC",
                "DATA",
                "TCP.SEGMENTS",
                "LLMNR",
                "DHCP",
                "NTP",
                "HTTP",
                "NBNS",
                "DATA-TEXT-LINES",
                "CLDAP",
                "MAILSLOT",
                "DRSUAPI",
                "DNS"
            ],
            "connection_type": "Externe",
            "classification": "Dangereuse",
            "attacks": []
        },
        {
            "ip": "172.17.8.255",
            "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "undetected": 32,
                "harmless": 62,
                "timeout": 0
            },
            "reputation": 0,
            "last_analysis_date": 1662795849,
            "country": "Unknown",
            "as_owner": "Unknown",
            "tags": [
                "private"
            ],
            "total_packets": 28,
            "targeted_machines": [],
            "protocols_used": [
                "NBNS",
                "MAILSLOT"
            ],
            "connection_type": "Externe",
            "classification": "Securise",
            "attacks": []
        },
        {
            "ip": "172.17.8.2",
            "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "undetected": 32,
                "harmless": 62,
                "timeout": 0
            },
            "reputation": 0,
            "last_analysis_date": 1737571479,
            "country": "Unknown",
            "as_owner": "Unknown",
            "tags": [
                "private"
            ],
            "total_packets": 869,
            "targeted_machines": [
                "172.17.8.109"
            ],
            "protocols_used": [
                "NBNS",
                "DCERPC",
                "DATA",
                "CLDAP",
                "TCP.SEGMENTS",
                "RPC_NETLOGON",
                "DHCP",
                "LSARPC",
                "EPM",
                "MAILSLOT",
                "DRSUAPI",
                "KERBEROS",
                "NTP",
                "TCP",
                "SMB2",
                "DNS",
                "SMB",
                "LDAP"
            ],
            "connection_type": "Externe",
            "classification": "Suspecte",
            "attacks": []
        },
        {
            "ip": "224.0.0.22",
            "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "undetected": 33,
                "harmless": 61,
                "timeout": 0
            },
            "reputation": -41,
            "last_analysis_date": 1743488788,
            "country": "Unknown",
            "as_owner": "Unknown",
            "tags": [
                "multicast"
            ],
            "total_packets": 8,
            "targeted_machines": [],
            "protocols_used": [
                "IGMP"
            ],
            "connection_type": "Externe",
            "classification": "S\u00e9curis\u00e9e",
            "attacks": []
        },
        {
            "ip": "224.0.0.252",
            "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "undetected": 32,
                "harmless": 62,
                "timeout": 0
            },
            "reputation": -51,
            "last_analysis_date": 1743477740,
            "country": "Unknown",
            "as_owner": "Unknown",
            "tags": [
                "suspicious-udp",
                "multicast"
            ],
            "total_packets": 8,
            "targeted_machines": [],
            "protocols_used": [
                "LLMNR"
            ],
            "connection_type": "Externe",
            "classification": "S\u00e9curis\u00e9e",
            "attacks": []
        },
        {
            "ip": "23.50.224.8",
            "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "undetected": 94,
                "harmless": 0,
                "timeout": 0
            },
            "reputation": 0,
            "last_analysis_date": 1743429004,
            "country": "US",
            "as_owner": "Akamai International B.V.",
            "tags": [],
            "total_packets": 9,
            "targeted_machines": [
                "172.17.8.109"
            ],
            "protocols_used": [
                "DATA-TEXT-LINES",
                "HTTP",
                "TCP"
            ],
            "connection_type": "Externe",
            "classification": "Suspecte",
            "attacks": []
        },
        {
            "ip": "239.255.255.250",
            "last_analysis_stats": {
                "malicious": 1,
                "suspicious": 0,
                "undetected": 33,
                "harmless": 60,
                "timeout": 0
            },
            "reputation": -145,
            "last_analysis_date": 1743476322,
            "country": "Unknown",
            "as_owner": "Unknown",
            "tags": [
                "multicast"
            ],
            "total_packets": 6,
            "targeted_machines": [],
            "protocols_used": [
                "SSDP"
            ],
            "connection_type": "Externe",
            "classification": "S\u00e9curis\u00e9e",
            "attacks": []
        },
        {
            "ip": "91.121.30.169",
            "last_analysis_stats": {
                "malicious": 1,
                "suspicious": 2,
                "undetected": 32,
                "harmless": 59,
                "timeout": 0
            },
            "reputation": 0,
            "last_analysis_date": 1743429004,
            "country": "FR",
            "as_owner": "OVH SAS",
            "tags": [],
            "total_packets": 187,
            "targeted_machines": [
                "172.17.8.109"
            ],
            "protocols_used": [
                "TCP.SEGMENTS",
                "HTTP",
                "TCP"
            ],
            "connection_type": "Externe",
            "classification": "Suspecte",
            "attacks": []
        },
        {
            "ip": "192.241.220.183",
            "last_analysis_stats": {
                "malicious": 13,
                "suspicious": 0,
                "undetected": 30,
                "harmless": 51,
                "timeout": 0
            },
            "reputation": -4,
            "last_analysis_date": 1743429004,
            "country": "US",
            "as_owner": "DIGITALOCEAN-ASN",
            "tags": [],
            "total_packets": 846,
            "targeted_machines": [
                "172.17.8.109"
            ],
            "protocols_used": [
                "TLS",
                "TCP.SEGMENTS",
                "TCP"
            ],
            "connection_type": "Externe",
            "classification": "Suspecte",
            "attacks": []
        },
        {
            "ip": "204.2.193.184",
            "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "undetected": 94,
                "harmless": 0,
                "timeout": 0
            },
            "reputation": 0,
            "last_analysis_date": 1743429004,
            "country": "US",
            "as_owner": "NTT-DATA-2914",
            "tags": [],
            "total_packets": 9,
            "targeted_machines": [
                "172.17.8.109"
            ],
            "protocols_used": [
                "HTTP",
                "TCP"
            ],
            "connection_type": "Externe",
            "classification": "Suspecte",
            "attacks": []
        },
        {
            "ip": "216.239.94.252",
            "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "undetected": 32,
                "harmless": 62,
                "timeout": 0
            },
            "reputation": 0,
            "last_analysis_date": 1743429004,
            "country": "CA",
            "as_owner": "CONCORDE",
            "tags": [],
            "total_packets": 1717,
            "targeted_machines": [
                "172.17.8.109"
            ],
            "protocols_used": [
                "TLS",
                "TCP.SEGMENTS",
                "DATA",
                "TCP"
            ],
            "connection_type": "Externe",
            "classification": "Suspecte",
            "attacks": []
        }
    ]
};

function generateIPList() {
    const ipListContainer = document.getElementById("ip-list");

    data.analysis_results.forEach(result => {
        const ipCard = document.createElement('div');
        ipCard.classList.add('ip-card');

        // IP Address
        const ipHeader = document.createElement('h2');
        ipHeader.textContent = `IP: ${result.ip}`;
        ipCard.appendChild(ipHeader);

        // Reputation
        const reputation = document.createElement('p');
        reputation.classList.add('reputation');
        reputation.textContent = `Réputation: ${result.reputation}`;
        ipCard.appendChild(reputation);

        // Country
        const country = document.createElement('p');
        country.textContent = `Pays: ${result.country}`;
        ipCard.appendChild(country);

        // AS Owner
        const asOwner = document.createElement('p');
        asOwner.textContent = `AS Owner: ${result.as_owner}`;
        ipCard.appendChild(asOwner);

        // Tags
        const tags = document.createElement('p');
        tags.textContent = `Tags: ${result.tags.join(', ')}`;
        ipCard.appendChild(tags);

        // Total Packets
        const totalPackets = document.createElement('p');
        totalPackets.textContent = `Total Packets: ${result.total_packets}`;
        ipCard.appendChild(totalPackets);

        // Targeted Machines
        const targetedMachines = document.createElement('p');
        targetedMachines.textContent = `Machines ciblées: ${result.targeted_machines.join(', ')}`;
        ipCard.appendChild(targetedMachines);

        // Protocols Used
        const protocolsUsed = document.createElement('p');
        protocolsUsed.textContent = `Protocoles utilisés: ${result.protocols_used.join(', ')}`;
        ipCard.appendChild(protocolsUsed);

        // Connection Type
        const connectionType = document.createElement('p');
        connectionType.textContent = `Type de connexion: ${result.connection_type}`;
        ipCard.appendChild(connectionType);

        // Classification
        const classification = document.createElement('p');
        classification.textContent = `Classification: ${result.classification}`;
        ipCard.appendChild(classification);

        // Analysis Stats (Malicious, Suspicious, Harmless, Undetected)
        const statsContainer = document.createElement('div');
        statsContainer.classList.add('stats');

        const statMalicious = document.createElement('div');
        statMalicious.classList.add('stat', 'malicious');
        statMalicious.textContent = `Malicious: ${result.last_analysis_stats.malicious}`;
        statsContainer.appendChild(statMalicious);

        const statSuspicious = document.createElement('div');
        statSuspicious.classList.add('stat', 'suspicious');
        statSuspicious.textContent = `Suspicious: ${result.last_analysis_stats.suspicious}`;
        statsContainer.appendChild(statSuspicious);

        const statHarmless = document.createElement('div');
        statHarmless.classList.add('stat', 'harmless');
        statHarmless.textContent = `Harmless: ${result.last_analysis_stats.harmless}`;
        statsContainer.appendChild(statHarmless);

        const statUndetected = document.createElement('div');
        statUndetected.classList.add('stat', 'undetected');
        statUndetected.textContent = `Undetected: ${result.last_analysis_stats.undetected}`;
        statsContainer.appendChild(statUndetected);

        ipCard.appendChild(statsContainer);

        // Append the IP card to the container
        ipListContainer.appendChild(ipCard);
    });
}

document.addEventListener('DOMContentLoaded', generateIPList);
