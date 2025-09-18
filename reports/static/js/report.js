document.addEventListener('DOMContentLoaded', function() {
    // Initialize charts
    const vulnerabilityCtx = document.getElementById('vulnerabilityChart');
    if (vulnerabilityCtx) {
        new Chart(vulnerabilityCtx, {
            type: 'bar',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    label: 'Vulnerabilities',
                    data: window.vulnerabilityData || [],
                    backgroundColor: [
                        '#DC2626', // red
                        '#F97316', // orange
                        '#FBBF24', // yellow
                        '#34D399'  // green
                    ]
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }
});