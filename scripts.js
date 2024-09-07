document.addEventListener('DOMContentLoaded', function() {
  const bombiarkaBtn = document.getElementById('bombiarka-btn');
  const finderkaBtn = document.getElementById('finderka-btn');
  const bombiarkaContent = document.getElementById('bombiarka');
  const finderkaContent = document.getElementById('finderka');
  
  // Domyślnie wyświetlamy zakładkę Bombiarka
  bombiarkaContent.style.display = 'block';

  // Przełączanie zakładek
  bombiarkaBtn.addEventListener('click', function() {
    bombiarkaContent.style.display = 'block';
    finderkaContent.style.display = 'none';
  });

  finderkaBtn.addEventListener('click', function() {
    bombiarkaContent.style.display = 'none';
    finderkaContent.style.display = 'block';
  });

  // Obsługa przycisku wyszukiwania
  document.getElementById('search-btn').addEventListener('click', function() {
    const phrase = document.getElementById('phrase').value;

    fetch(`/search?phrase=${encodeURIComponent(phrase)}`)
      .then(response => response.json())
      .then(data => {
        const resultsDiv = document.getElementById('results');
        resultsDiv.innerHTML = '';

        data.results.forEach(result => {
          const resultDiv = document.createElement('div');
          resultDiv.innerHTML = `
            <p><strong>Nick:</strong> ${result.nick}</p>
            <p><strong>IP:</strong> ${result.ip}</p>
            <p><strong>Plik:</strong> ${result.file}</p>
            <p><strong>Ping:</strong> ${result.ping}</p>
            <hr>
          `;
          resultsDiv.appendChild(resultDiv);
        });
      });
  });
});
