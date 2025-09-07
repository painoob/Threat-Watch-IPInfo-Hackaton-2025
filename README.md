# ThreatWatch: Real-Time IP Threat Intelligence Dashboard

![ThreatWatch Dashboard](https://img.shields.io/badge/Status-Ready_for_Hackathon-brightgreen)
![IPinfo Lite](https://img.shields.io/badge/Powered%20by-IPinfo%20Lite-blue)
![Hackathon](https://img.shields.io/badge/Hackathon-IPinfo%202025-orange)

A comprehensive threat intelligence dashboard that leverages IPinfo Lite's geolocation and ASN data to provide real-time security analysis of IP addresses. Built for the IPinfo Lite Hackathon 2025.

## 🚀 Features

- **Multi-Source Threat Analysis**: Integrates with AbuseIPDB, VirusTotal, and IPQualityScore
- **Interactive Geolocation Mapping**: Visualize threats on a world map with color-coded markers
- **Real-Time IP Enrichment**: Process up to 100 IPs per request with 24-hour caching
- **Threat Scoring System**: Automatic confidence scoring based on multiple threat feeds
- **Export Capabilities**: Generate CSV reports and IOC (Indicators of Compromise) lists
- **Responsive Dashboard**: Clean, modern interface with real-time statistics

## 📸 Screenshot

### Demo Online: [https://oob.xx.kg](https://oob.xx.kg)

![Dashboard Preview](https://github.com/painoob/Threat-Watch-IPInfo-Hackaton-2025/blob/main/preview.jpg)

## 🛠️ Installation

### Prerequisites
- PHP 7.4 or higher
- Web server (Apache/Nginx)
- Composer (optional)

### Quick Start

1. **Clone the repository**
```
git clone https://github.com/painoob/Threat-Watch-IPInfo-Hackaton-2025.git
cd Threat-Watch-IPInfo-Hackaton-2025
copy all files to your webserver root
```

## 🔧 Configuration

### Set IPinfo token (required)
export IPINFO_TOKEN=your_ipinfo_token_here

### Optional: Set threat intelligence API keys
- export ABUSEIPDB_KEY=your_abuseipdb_key_here
- export VIRUSTOTAL_KEY=your_virustotal_key_here
- export IPQUALITYSCORE_KEY=your_ipqualityscore_key_here
- Ensure cache directory is writable
- chmod 755 cache
- Deploy to your web server
- Upload files to your web directory
- Ensure PHP is properly configured

## 🎯 Usage

### Basic IP Analysis
* Access the dashboard through your web browser
* Paste IP addresses in the textarea (one per line or comma-separated)
* Click "Enrich & Scan" to analyze the IPs
* View results on the map and in the tables

### Exporting Data
* CSV Export: Download comprehensive reports with all enrichment data
* IOC Export: Export only malicious IPs for blocklist integration

### API Endpoints
* The system provides these API endpoints:
* POST api.php?action=enrich - Enrich IP addresses
* GET api.php?action=clear_cache - Clear cached data

## 📊 How It Works
- IP Validation: Validates input IP addresses
- Geolocation Lookup: Uses IPinfo Lite for location and ASN data
- Threat Intelligence: Queries multiple security APIs
- Threat Scoring: Calculates confidence scores based on results
- Visualization: Displays data on interactive map and tables
- Caching: Stores results for 24 hours to optimize performance

## 🏗️ Architecture

1. Frontend (HTML/CSS/JS)
    ↓
2. API Layer (PHP)
    ↓
3. IPinfo Lite API → Geolocation & ASN Data
    ↓
4. Threat Intelligence APIs → Security Analysis
    ↓
5. Data Processing → Threat Scoring & Visualization

## 🔒 Security Features
* Input validation and sanitization
* Rate limiting through caching
* Secure API key handling
* No sensitive data storage

## 🌟 Hackathon Highlights
This project demonstrates:
- Innovative Use of IPdata: Combines geolocation with threat intelligence
- Real-World Application: Solves actual cybersecurity challenges
- Scalable Architecture: Handles batch processing efficiently
- User-Friendly Design: Intuitive interface for technical users

## 📈 Performance
- Processes 100 IPs in under 30 seconds
- 24-hour caching reduces API calls
- Lightweight and responsive design
- Minimal server requirements

## 🙏 Acknowledgments
- IPinfo for providing the Lite API and hosting the hackathon
- AbuseIPDB, VirusTotal, and IPQualityScore for their threat intelligence APIs
- Leaflet.js for the mapping functionality
- OpenStreetMap for map tiles

## 🐛 Troubleshooting

### Common Issues

**No API token configured**
Solution: Set the IPINFO_TOKEN environment variable

**Cache directory not writable**
Solution: chmod 755 cache on the directory

**API rate limiting**
Solution: The system includes automatic caching to minimize calls

## 📮 Contact

### For questions about this project:
Email: contato@painoob.com

Built with ❤️ for the IPinfo Lite Hackathon 2025

*September 4 - October 6, 2025*
