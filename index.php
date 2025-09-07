<?php require_once __DIR__.'/config.php'; ?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Threat Watch - IPInfo Hackathon 2025</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,'Helvetica Neue',Arial;margin:0;padding:0;color:#111}
header{background:#111;color:#fff;padding:1rem 1.25rem}
.container{display:grid;grid-template-columns:1fr 380px;gap:1rem;padding:1rem}
.card{background:#fff;border-radius:8px;padding:1rem;box-shadow:0 4px 14px rgba(0,0,0,0.06)}
#map{height:600px;border-radius:8px}
textarea{width:100%;height:160px}
table{width:100%;border-collapse:collapse}
table th, table td{padding:6px;border-bottom:1px solid #eee}
.btn{display:inline-block;padding:8px 12px;border-radius:6px;background:#111;color:#fff;text-decoration:none}
.loading{opacity:0.6;pointer-events:none}
.malicious{background-color:#ffebee;border-left:4px solid #f44336}
.suspicious{background-color:#fff8e1;border-left:4px solid #ffc107}
.clean{background-color:#e8f5e9;border-left:4px solid #4caf50}
.threat-badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:0.8rem;font-weight:500}
.threat-malicious{background:#f44336;color:white}
.threat-suspicious{background:#ff9800;color:white}
.threat-clean{background:#4caf50;color:white}
.config-warning{background:#fff3cd;color:#856404;padding:12px;border-radius:6px;margin-bottom:1rem;border-left:4px solid #ffc107}
</style>
</head>
<body>
<header>
<div style="display:flex;align-items:center;justify-content:space-between">
<h1 style="margin:0;font-size:1.1rem">Threat Watch</h1>
<div>IPInfo: <strong>Hackathon 2025</strong></div>
</div>
</header>

<div class="container">
<main class="card">
<section>
<h2>Map</h2>
<div id="map"></div>
</section>

<section style="margin-top:1rem">
<h3>Recent Enrichments</h3>
<div id="recent"></div>
</section>
</main>

<aside>
<?php if (!is_threat_intel_configured()): ?>
<div class="config-warning">
<strong>Warning:</strong> Threat intelligence APIs are not configured. 
<a href="#" id="showConfigHelp">Click here</a> for setup instructions.
</div>
<div id="configHelp" style="display:none;margin-bottom:1rem" class="card">
<h4>API Configuration</h4>
<p>To enable threat detection, set these environment variables:</p>
<ul>
<li>ABUSEIPDB_KEY - Get from <a href="https://www.abuseipdb.com/" target="_blank">AbuseIPDB</a></li>
<li>VIRUSTOTAL_KEY - Get from <a href="https://www.virustotal.com/" target="_blank">VirusTotal</a></li>
<li>IPQUALITYSCORE_KEY - Get from <a href="https://www.ipqualityscore.com/" target="_blank">IPQualityScore</a></li>
</ul>
</div>
<?php endif; ?>

<div class="card">
<h3>Enrich IPs</h3>
<form id="enrichForm">
<label>Paste IPs (one per line, or comma separated):</label>
<textarea id="ips" placeholder="8.8.8.8&#10;1.1.1.1&#10;185.220.101.204"></textarea>
<div style="margin-top:8px">
<button class="btn" type="submit">Enrich & Scan</button>
<a href="#" id="clearCache" style="margin-left:8px">Clear Cache</a>
</div>
</form>
</div>

<div class="card" style="margin-top:1rem">
<h3>Threat Summary</h3>
<div id="threatSummary">
<p>No data yet. Analyze some IPs to see threat statistics.</p>
</div>
</div>

<div class="card" style="margin-top:1rem">
<h3>Top Countries</h3>
<div id="countries"></div>
</div>

<div class="card" style="margin-top:1rem">
<h3>Top ASNs</h3>
<div id="asns"></div>
</div>

<div class="card" style="margin-top:1rem">
<h3>Export</h3>
<button class="btn" id="exportCsv">Export CSV</button>
<button class="btn" id="exportIoc" style="margin-left:8px">Export IOC</button>
</div>
</aside>
</div>

<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
// Initialize map
const map = L.map('map').setView([20, 0], 2);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '&copy; OpenStreetMap contributors'
}).addTo(map);
const markers = L.layerGroup().addTo(map);

// Store enrichment data
let enrichmentData = [];
let countryStats = {};
let asnStats = {};
let threatStats = {
    malicious: 0,
    suspicious: 0,
    clean: 0,
    total: 0
};

// Toggle config help
document.getElementById('showConfigHelp')?.addEventListener('click', (e) => {
    e.preventDefault();
    document.getElementById('configHelp').style.display = 'block';
});

// Form submission
document.getElementById('enrichForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const ipsText = document.getElementById('ips').value.trim();
    if (!ipsText) return;

    // Show loading state
    document.getElementById('enrichForm').classList.add('loading');
    
    try {
        const response = await fetch('api.php?action=enrich', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: 'ips=' + encodeURIComponent(ipsText)
        });
        
        const data = await response.json();
        if (data.ok) {
            processResults(data.results);
            updateDashboard();
        } else {
            alert('Error: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        alert('Network error: ' + error.message);
    } finally {
        document.getElementById('enrichForm').classList.remove('loading');
    }
});

// Clear cache
document.getElementById('clearCache').addEventListener('click', async (e) => {
    e.preventDefault();
    if (confirm('Clear all cached data?')) {
        try {
            const response = await fetch('api.php?action=clear_cache');
            const data = await response.json();
            if (data.ok) {
                alert('Cache cleared: ' + data.cleared + ' files');
                location.reload();
            }
        } catch (error) {
            alert('Error clearing cache: ' + error.message);
        }
    }
});

// Export CSV
document.getElementById('exportCsv').addEventListener('click', () => {
    if (enrichmentData.length === 0) {
        alert('No data to export');
        return;
    }
    
    const headers = ['IP', 'Country', 'City', 'Region', 'ASN', 'Organization', 'Threat Status', 'Confidence Score', 'Abuse Score', 'VT Malicious'];
    let csv = headers.join(',') + '\n';
    
    enrichmentData.forEach(item => {
        const threat = item.threat_intel || {};
        const row = [
            item.ip,
            item.country || '',
            item.city || '',
            item.region || '',
            item.asn?.asn || '',
            item.asn?.name || item.org || '',
            threat.is_malicious ? 'Malicious' : (threat.confidence > 20 ? 'Suspicious' : 'Clean'),
            threat.confidence || 0,
            threat.abuseipdb?.abuseConfidenceScore || 0,
            threat.virustotal?.malicious || 0
        ].map(field => `"${String(field).replace(/"/g, '""')}"`).join(',');
        csv += row + '\n';
    });
    
    downloadFile(csv, 'ip-threat-report.csv', 'text/csv');
});

// Export IOC
document.getElementById('exportIoc').addEventListener('click', () => {
    if (enrichmentData.length === 0) {
        alert('No data to export');
        return;
    }
    
    const maliciousIps = enrichmentData.filter(item => 
        item.threat_intel?.is_malicious
    ).map(item => item.ip);
    
    if (maliciousIps.length === 0) {
        alert('No malicious IPs to export');
        return;
    }
    
    const iocContent = maliciousIps.join('\n');
    downloadFile(iocContent, 'malicious-ips.ioc', 'text/plain');
});

// Download helper
function downloadFile(content, fileName, contentType) {
    const blob = new Blob([content], { type: contentType });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    a.click();
    window.URL.revokeObjectURL(url);
}

// Process results
function processResults(results) {
    enrichmentData = [];
    countryStats = {};
    asnStats = {};
    threatStats = { malicious: 0, suspicious: 0, clean: 0, total: 0 };
    
    Object.entries(results).forEach(([ip, data]) => {
        if (data.error) return;
        
        const enriched = { ip, ...data };
        enrichmentData.push(enriched);
        
        // Update country stats
        if (data.country) {
            countryStats[data.country] = (countryStats[data.country] || 0) + 1;
        }
        
        // Update ASN stats
        const asn = data.asn?.asn || data.org;
        if (asn) {
            asnStats[asn] = (asnStats[asn] || 0) + 1;
        }
        
        // Update threat stats
        threatStats.total++;
        const threat = data.threat_intel || {};
        if (threat.is_malicious) {
            threatStats.malicious++;
        } else if (threat.confidence > 20) {
            threatStats.suspicious++;
        } else {
            threatStats.clean++;
        }
        
        // Add marker to map if we have coordinates
        if (data.loc) {
            const [lat, lng] = data.loc.split(',').map(Number);
            if (!isNaN(lat) && !isNaN(lng)) {
                let markerColor = 'green';
                if (threat.is_malicious) {
                    markerColor = 'red';
                } else if (threat.confidence > 20) {
                    markerColor = 'orange';
                }
                
                const marker = L.marker([lat, lng], {
                    icon: L.divIcon({
                        html: `<div style="background-color:${markerColor}; width:12px; height:12px; border-radius:50%; border:2px solid white; box-shadow:0 0 2px black;"></div>`,
                        className: '',
                        iconSize: [12, 12]
                    })
                }).addTo(markers);
                
                let popupContent = `<b>${ip}</b><br>${data.city || ''}, ${data.country || ''}`;
                if (threat.is_malicious) {
                    popupContent += `<br><span class="threat-badge threat-malicious">Malicious</span>`;
                } else if (threat.confidence > 20) {
                    popupContent += `<br><span class="threat-badge threat-suspicious">Suspicious</span>`;
                }
                
                marker.bindPopup(popupContent);
            }
        }
    });
}

// Update dashboard
function updateDashboard() {
    // Update recent enrichments
    const recentDiv = document.getElementById('recent');
    if (enrichmentData.length > 0) {
        recentDiv.innerHTML = `
            <table>
                <tr><th>IP</th><th>Country</th><th>Threat</th><th>Confidence</th></tr>
                ${enrichmentData.slice(-10).map(item => {
                    const threat = item.threat_intel || {};
                    let threatClass = 'clean';
                    let threatText = 'Clean';
                    let threatBadge = 'threat-clean';
                    
                    if (threat.is_malicious) {
                        threatClass = 'malicious';
                        threatText = 'Malicious';
                        threatBadge = 'threat-malicious';
                    } else if (threat.confidence > 20) {
                        threatClass = 'suspicious';
                        threatText = 'Suspicious';
                        threatBadge = 'threat-suspicious';
                    }
                    
                    return `
                        <tr class="${threatClass}">
                            <td>${item.ip}</td>
                            <td>${item.country || 'N/A'}</td>
                            <td><span class="threat-badge ${threatBadge}">${threatText}</span></td>
                            <td>${threat.confidence ? Math.round(threat.confidence) : '0'}%</td>
                        </tr>
                    `;
                }).join('')}
            </table>
        `;
    } else {
        recentDiv.innerHTML = '<p>No enrichments yet</p>';
    }
    
    // Update threat summary
    const threatSummaryDiv = document.getElementById('threatSummary');
    if (threatStats.total > 0) {
        threatSummaryDiv.innerHTML = `
            <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                <div style="text-align: center;">
                    <div style="font-size: 1.5rem; color: #f44336;">${threatStats.malicious}</div>
                    <div>Malicious</div>
                </div>
                <div style="text-align: center;">
                    <div style="font-size: 1.5rem; color: #ff9800;">${threatStats.suspicious}</div>
                    <div>Suspicious</div>
                </div>
                <div style="text-align: center;">
                    <div style="font-size: 1.5rem; color: #4caf50;">${threatStats.clean}</div>
                    <div>Clean</div>
                </div>
            </div>
            <div style="background: #f0f0f0; height: 20px; border-radius: 10px; overflow: hidden;">
                <div style="height: 100%; width: ${(threatStats.malicious / threatStats.total) * 100}%; background: #f44336; display: inline-block;"></div>
                <div style="height: 100%; width: ${(threatStats.suspicious / threatStats.total) * 100}%; background: #ff9800; display: inline-block;"></div>
                <div style="height: 100%; width: ${(threatStats.clean / threatStats.total) * 100}%; background: #4caf50; display: inline-block;"></div>
            </div>
            <div style="margin-top: 8px; text-align: center;">
                Total IPs: ${threatStats.total}
            </div>
        `;
    } else {
        threatSummaryDiv.innerHTML = '<p>No data yet. Analyze some IPs to see threat statistics.</p>';
    }
    
    // Update top countries
    const countriesDiv = document.getElementById('countries');
    const sortedCountries = Object.entries(countryStats)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5);
    
    if (sortedCountries.length > 0) {
        countriesDiv.innerHTML = `
            <table>
                ${sortedCountries.map(([country, count]) => `
                    <tr><td>${country}</td><td>${count}</td></tr>
                `).join('')}
            </table>
        `;
    } else {
        countriesDiv.innerHTML = '<p>No country data</p>';
    }
    
    // Update top ASNs
    const asnsDiv = document.getElementById('asns');
    const sortedAsns = Object.entries(asnStats)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5);
    
    if (sortedAsns.length > 0) {
        asnsDiv.innerHTML = `
            <table>
                ${sortedAsns.map(([asn, count]) => `
                    <tr><td>${asn}</td><td>${count}</td></tr>
                `).join('')}
            </table>
        `;
    } else {
        asnsDiv.innerHTML = '<p>No ASN data</p>';
    }
}

// Initial load
updateDashboard();
</script>
</body>
</html>