document.addEventListener('DOMContentLoaded', function() {
    // Project calculator
    const calcButton = document.getElementById('calculate-cost');
    if (calcButton) {
        calcButton.addEventListener('click', function() {
            const area = document.getElementById('area_size').value;
            if (area && !isNaN(area) && area > 0) {
                const cost = area * 100;
                document.getElementById('cost-estimate').innerText = `Estimated Cost: £${cost.toFixed(2)} (Contact for accurate quote)`;
            } else {
                document.getElementById('cost-estimate').innerText = 'Please enter a valid area size.';
            }
        });
    }

    // Search suggestions
    const searchInput = document.getElementById('search-input');
    const suggestionsList = document.getElementById('suggestions');
    if (searchInput && suggestionsList) {
        searchInput.addEventListener('input', function() {
            const query = this.value;
            if (query.length > 1) {
                fetch(`/search_suggestions?q=${encodeURIComponent(query)}`)
                    .then(response => response.json())
                    .then(data => {
                        suggestionsList.innerHTML = '';
                        data.forEach(suggestion => {
                            const li = document.createElement('li');
                            li.className = 'list-group-item';
                            li.textContent = suggestion;
                            li.addEventListener('click', () => {
                                searchInput.value = suggestion;
                                suggestionsList.innerHTML = '';
                            });
                            suggestionsList.appendChild(li);
                        });
                    });
            } else {
                suggestionsList.innerHTML = '';
            }
        });
    }
});