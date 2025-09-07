
<?php
// Basic configuration. Prefer to set IPINFO_TOKEN in environment and leave empty here.
// Example: putenv('IPINFO_TOKEN=555555555555'); in your server or use cPanel environment vars.

define('IPINFO_TOKEN', getenv('IPINFO_TOKEN') ?: '555555555555');
define('CACHE_DIR', __DIR__ . '/cache');
define('CACHE_TTL', 24 * 3600); // seconds (24h)

// Threat Intelligence APIs (Set these in your environment variables)
define('ABUSEIPDB_KEY', getenv('ABUSEIPDB_KEY') ?: '55555555555555555555555555555555555555555555555555555555555555555555555555555');
define('VIRUSTOTAL_KEY', getenv('VIRUSTOTAL_KEY') ?: '55555555555555555555555555555555555555555555555555555555555555555555555555555');
define('IPQUALITYSCORE_KEY', getenv('IPQUALITYSCORE_KEY') ?: '55555555555555555555555555555555555555555555555555555555555555555555555555555');

// Create cache dir if not exists
if (!is_dir(CACHE_DIR)) {
mkdir(CACHE_DIR, 0755, true);
}

// Simple helper
function cache_path($key){
return CACHE_DIR . '/'.preg_replace('/[^a-z0-9_\-\.]/i','_', $key) . '.json';
}

// Helper to check if API keys are configured
function is_threat_intel_configured() {
    return !empty(ABUSEIPDB_KEY) || !empty(VIRUSTOTAL_KEY) || !empty(IPQUALITYSCORE_KEY);
}
?>