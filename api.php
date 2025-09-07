<?php
require_once __DIR__.'/config.php';

header('Content-Type: application/json; charset=utf-8');

$action = $_GET['action'] ?? ($_POST['action'] ?? '');

if ($action === 'enrich') {
    // Accept single IP or newline separated list in POST 'ips'
    $ips_raw = trim($_POST['ips'] ?? '');
    if (empty($ips_raw)) {
        echo json_encode(['error'=>'no input']);
        exit;
    }
    $lines = preg_split('/[\r\n,\s]+/', $ips_raw, -1, PREG_SPLIT_NO_EMPTY);
    $ips = array_slice(array_unique($lines), 0, 100); // Reduced cap for safety

    $results = [];
    foreach ($ips as $ip) {
        // Validate IP address
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $results[$ip] = ['error' => 'invalid_ip'];
            continue;
        }
        
        $key = 'ipinfo_'. $ip;
        $cache_file = cache_path($key);
        $use_cache = false;
        
        if (file_exists($cache_file) && (time() - filemtime($cache_file) < CACHE_TTL)) {
            $data = json_decode(file_get_contents($cache_file), true);
            if ($data) {
                $use_cache = true;
                $results[$ip] = $data;
            }
        }
        
        if (!$use_cache) {
            // Use the full API endpoint instead of /lite/ for more complete data
            $url = "https://ipinfo.io/".urlencode($ip)."?token=".urlencode(IPINFO_TOKEN);
            $ch = curl_init($url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 10);
            curl_setopt($ch, CURLOPT_USERAGENT, 'IPInfo-Hackathon-2025/1.0');
            $resp = curl_exec($ch);
            $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $err = curl_errno($ch) ? curl_error($ch) : null;
            curl_close($ch);
            
            if ($resp === false || $http_code !== 200) {
                $results[$ip] = [
                    'error' => "api_error", 
                    'http_code' => $http_code,
                    'raw_error'=> $err
                ];
            } else {
                $json = json_decode($resp, true);
                if (!$json) {
                    $results[$ip] = ['error' => 'invalid_json', 'raw' => $resp];
                } else {
                    // Parse ASN information if available
                    if (isset($json['org'])) {
                        $org_parts = explode(' ', $json['org'], 2);
                        $json['asn'] = [
                            'asn' => $org_parts[0],
                            'name' => $org_parts[1] ?? ''
                        ];
                    }
                    
                    // Add threat intelligence data if APIs are configured
                    if (is_threat_intel_configured()) {
                        $json['threat_intel'] = get_threat_intelligence($ip);
                    }
                    
                    $results[$ip] = $json;
                    // atomic write
                    file_put_contents($cache_file . '.tmp', json_encode($json));
                    rename($cache_file . '.tmp', $cache_file);
                }
            }
        } else {
            // Even if using cache, check if we need to add threat intelligence
            if (is_threat_intel_configured() && !isset($results[$ip]['threat_intel'])) {
                $results[$ip]['threat_intel'] = get_threat_intelligence($ip);
                // Update cache with threat intel data
                file_put_contents($cache_file . '.tmp', json_encode($results[$ip]));
                rename($cache_file . '.tmp', $cache_file);
            }
        }
    }
    echo json_encode(['ok'=>true, 'count'=>count($results), 'results'=>$results]);
    exit;
}

if ($action === 'clear_cache') {
    // simple admin action — consider protecting in production
    $files = glob(CACHE_DIR.'/*.json');
    $cleared = 0;
    foreach ($files as $f) {
        if (@unlink($f)) $cleared++;
    }
    echo json_encode(['ok'=>true, 'cleared'=>$cleared]);
    exit;
}

// Function to get threat intelligence data from multiple sources
function get_threat_intelligence($ip) {
    $threat_data = [
        'abuseipdb' => check_abuseipdb($ip),
        'virustotal' => check_virustotal($ip),
        'ipqualityscore' => check_ipqualityscore($ip),
        'is_malicious' => false,
        'confidence' => 0,
        'sources' => 0
    ];
    
    // Calculate overall threat score
    $malicious_sources = 0;
    $total_confidence = 0;
    
    if (!empty($threat_data['abuseipdb']['abuseConfidenceScore'])) {
        if ($threat_data['abuseipdb']['abuseConfidenceScore'] > 25) {
            $malicious_sources++;
        }
        $total_confidence += $threat_data['abuseipdb']['abuseConfidenceScore'];
    }
    
    if (!empty($threat_data['virustotal']['malicious']) && $threat_data['virustotal']['malicious'] > 0) {
        $malicious_sources++;
        $total_confidence += ($threat_data['virustotal']['malicious'] * 20); // Scale VT malicious count
    }
    
    if (!empty($threat_data['ipqualityscore']['fraud_score']) && $threat_data['ipqualityscore']['fraud_score'] > 50) {
        $malicious_sources++;
        $total_confidence += $threat_data['ipqualityscore']['fraud_score'];
    }
    
    // Determine if IP is malicious
    $threat_data['sources'] = $malicious_sources;
    $threat_data['confidence'] = $total_confidence / max(1, $malicious_sources);
    $threat_data['is_malicious'] = $malicious_sources >= 1;
    
    return $threat_data;
}

// Check IP against AbuseIPDB
function check_abuseipdb($ip) {
    if (empty(ABUSEIPDB_KEY)) return [];
    
    $url = "https://api.abuseipdb.com/api/v2/check";
    $params = [
        'ipAddress' => $ip,
        'maxAgeInDays' => 90,
        'verbose' => ''
    ];
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url . '?' . http_build_query($params));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Key: ' . ABUSEIPDB_KEY,
        'Accept: application/json'
    ]);
    
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($http_code === 200) {
        $data = json_decode($response, true);
        return $data['data'] ?? [];
    }
    
    return ['error' => 'API error', 'code' => $http_code];
}

// Check IP against VirusTotal
function check_virustotal($ip) {
    if (empty(VIRUSTOTAL_KEY)) return [];
    
    $url = "https://www.virustotal.com/api/v3/ip_addresses/" . urlencode($ip);
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'x-apikey: ' . VIRUSTOTAL_KEY
    ]);
    
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($http_code === 200) {
        $data = json_decode($response, true);
        return $data['data']['attributes']['last_analysis_stats'] ?? [];
    }
    
    return ['error' => 'API error', 'code' => $http_code];
}

// Check IP against IPQualityScore
function check_ipqualityscore($ip) {
    if (empty(IPQUALITYSCORE_KEY)) return [];
    
    $url = "https://www.ipqualityscore.com/api/json/ip/" . 
           IPQUALITYSCORE_KEY . "/" . urlencode($ip) . 
           "?strictness=1&allow_public_access_points=true&fast=true&lighter_penalties=true";
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($http_code === 200) {
        return json_decode($response, true);
    }
    
    return ['error' => 'API error', 'code' => $http_code];
}

http_response_code(400);
echo json_encode(['error'=>'unknown action']);
?>