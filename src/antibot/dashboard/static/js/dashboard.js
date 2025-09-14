/**
 * AntiBotLab Dashboard JavaScript
 */

// Auto-refresh stats every 30 seconds
let statsInterval = null;

function startStatsRefresh() {
    statsInterval = setInterval(async () => {
        try {
            const response = await fetch('/api/stats');
            const data = await response.json();

            // Update stat cards if they exist
            const cards = document.querySelectorAll('.stat-card');
            if (cards.length >= 4) {
                cards[0].querySelector('.text-3xl').textContent = data.total_scans;
                cards[1].querySelector('.text-3xl').textContent = data.sites_tracked;
                cards[2].querySelector('.text-3xl').textContent = data.bypass_rate.toFixed(1) + '%';
            }
        } catch (e) {
            // Silently fail on stats refresh
        }
    }, 30000);
}

// Start auto-refresh on dashboard page
if (document.querySelector('.stat-card')) {
    startStatsRefresh();
}

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
    // Ctrl+K: Focus scan URL input
    if (e.ctrlKey && e.key === 'k') {
        e.preventDefault();
        const urlInput = document.getElementById('scanUrl');
        if (urlInput) {
            urlInput.focus();
            urlInput.select();
        }
    }

    // Escape: Close any open details
    if (e.key === 'Escape') {
        document.querySelectorAll('details[open]').forEach(d => d.removeAttribute('open'));
    }
});

// Toast notifications
function showToast(message, type = 'info') {
    const colors = {
        info: 'border-neon-blue text-neon-blue',
        success: 'border-neon-green text-neon-green',
        error: 'border-neon-red text-neon-red',
        warning: 'border-neon-yellow text-neon-yellow',
    };

    const toast = document.createElement('div');
    toast.className = `fixed bottom-4 right-4 px-4 py-2 bg-dark-800 border rounded text-sm z-50 ${colors[type] || colors.info}`;
    toast.textContent = message;
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// Cleanup on page leave
window.addEventListener('beforeunload', () => {
    if (statsInterval) clearInterval(statsInterval);
});
