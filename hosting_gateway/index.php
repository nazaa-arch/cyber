<?php
/**
 * WAYANG Reverse Proxy Gateway untuk cyber.steamcraft.online
 * Diletakkan di direktori subdomain cyber.steamcraft.online pada cPanel Anymhost.
 * Menghubungkan pengunjung cyber.steamcraft.online (dengan SSL Let's Encrypt)
 * ke backend mesin pertahanan WAYANG Dalang Console.
 */

// Target URL backend cloud 24/7 (Render)
$backend_url = "https://wayang-c4isr.onrender.com";

$request_uri = $_SERVER['REQUEST_URI'];
$target_url = rtrim($backend_url, '/') . $request_uri;

$method = $_SERVER['REQUEST_METHOD'];
$headers = [];

// Teruskan semua request headers dari client
if (function_exists('getallheaders')) {
    foreach (getallheaders() as $name => $val) {
        $name_lower = strtolower($name);
        if ($name_lower !== 'host' && $name_lower !== 'content-length') {
            $headers[] = "$name: $val";
        }
    }
}
$headers[] = "Host: " . parse_url($backend_url, PHP_URL_HOST);
$headers[] = "ngrok-skip-browser-warning: 1";
$headers[] = "X-Forwarded-Host: cyber.steamcraft.online";
$headers[] = "X-Forwarded-Proto: https";

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $target_url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HEADER, true);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_TIMEOUT, 60);

if ($method === 'POST' || $method === 'PUT' || $method === 'PATCH') {
    $input = file_get_contents('php://input');
    curl_setopt($ch, CURLOPT_POSTFIELDS, $input);
}

$response = curl_exec($ch);
if (curl_errno($ch)) {
    http_response_code(502);
    echo "<h1>502 Bad Gateway - WAYANG Dalang Backend Offline</h1>";
    echo "<p>Gagal terhubung ke node lokal WAYANG: " . htmlspecialchars(curl_error($ch)) . "</p>";
    curl_close($ch);
    exit;
}

$header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$header_text = substr($response, 0, $header_size);
$body = substr($response, $header_size);
curl_close($ch);

// Set status HTTP
http_response_code($http_code);

// Teruskan response headers (Content-Type, Content-Disposition untuk download .docx, dll)
foreach (explode("\r\n", $header_text) as $hdr) {
    if (empty($hdr)) continue;
    $hdr_lower = strtolower($hdr);
    if (strpos($hdr_lower, 'transfer-encoding:') === 0) continue;
    if (strpos($hdr_lower, 'content-security-policy:') === 0) continue;
    header($hdr, false);
}

echo $body;
