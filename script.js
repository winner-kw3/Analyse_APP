function generateIPList(data) {
    const ipListContainer = document.getElementById("ip-list");

    if (!data || !data.analysis_results) 
        {
        console.error("Mal formater ou pas de donné dans le json");
        return;
    }

    data.analysis_results.forEach(result => {
        const ipCard = document.createElement('div');
        ipCard.classList.add('ip-card');

        const ipHeader = document.createElement('h2');
        ipHeader.textContent = `IP: ${result.ip}`;
        ipCard.appendChild(ipHeader);

        const reputation = document.createElement('p');
        reputation.classList.add('reputation');
        reputation.textContent = `Réputation: ${result.reputation}`;
        ipCard.appendChild(reputation);

        const country = document.createElement('p');
        country.textContent = `Pays: ${result.country}`;
        ipCard.appendChild(country);

        const asOwner = document.createElement('p');
        asOwner.textContent = `AS Owner: ${result.as_owner}`;
        ipCard.appendChild(asOwner);

        const tags = document.createElement('p');
        tags.textContent = `Tags: ${result.tags.join(', ')}`;
        ipCard.appendChild(tags);

        const statsContainer = document.createElement('div');
        statsContainer.classList.add('stats');

        const statMalicious = document.createElement('div');
        statMalicious.classList.add('stat', 'malicia');
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
        ipListContainer.appendChild(ipCard);
    });
}

fetch('http://localhost:5000/api/analyses')
  .then(response => 
    {
    if (!response.ok) 
        {
        throw new Error('Pas réussi a recup les données du json');
        }
    return response.json();
  })

  .then(data => 
    {
    console.log('Données récupérées:', data);
    generateIPList(data);
    })
  .catch(error => 
    {
    console.error('fichier JSON erreur:', error);
    });

document.addEventListener('DOMContentLoaded', () => 
    {
    console.log("Good");
    });