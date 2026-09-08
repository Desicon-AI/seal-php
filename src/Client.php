<?php

namespace Desicon\Seal;

class Client
{
    private static $apiKey;
    private static $signingSecret;
    private static $appName;
    private static $environment;
    private static $endpoint;
    private static $wafConfig = [];
    private static $startTime;
    private static $initialized = false;
    public static $heartbeatDeliveryOK = null;

    // Default WAF Config
    private static $defaultWaf = [
        'trustProxyHeaders' => false,
        'sqli' => ['action' => 'report'],
        'honeypot' => ['action' => 'report'],
        'xss' => ['action' => 'report'],
        'geoBlocking' => ['blockedCountries' => [], 'action' => 'report'],
        'maliciousScanners' => ['action' => 'report'],
        'methodTampering' => ['action' => 'report'],
        'payloadOverflow' => ['maxPayloadSize' => 5242880, 'action' => 'report'],
        'pathTraversal' => ['action' => 'report']
    ];

    public static function init($options = [])
    {
        if (self::$initialized) {
            return;
        }

        self::$apiKey = $options['apiKey'] ?? null;
        self::$signingSecret = $options['signingSecret'] ?? null;
        self::$appName = $options['appName'] ?? 'php-app';
        self::$environment = $options['environment'] ?? 'production';
        
        $sandbox = $options['sandbox'] ?? false;
        if ($sandbox) {
            self::$endpoint = 'https://sealengine.desicon.ai/api/v1/sandbox/ingest';
        } else {
            self::$endpoint = $options['endpoint'] ?? 'https://sealengine.desicon.ai/api/v1/ingest';
        }
        
        $waf = $options['waf'] ?? [];
        self::$wafConfig = array_replace_recursive(self::$defaultWaf, $waf);

        self::$startTime = round(microtime(true) * 1000);
        self::$initialized = true;

        if (!self::$apiKey) {
            error_log("[Seal] Missing API Key. Crashes will not be reported.");
        }

        // 1. Hook PHP Error & Exception Handlers
        set_exception_handler([__CLASS__, 'handleException']);
        set_error_handler([__CLASS__, 'handleError']);
        register_shutdown_function([__CLASS__, 'handleFatalError']);

        // 2. Execute Zero-Latency WAF
        if (PHP_SAPI !== 'cli') self::runSecurityEngine();

        // Liveness requires an independent cron/scheduler, not incoming web traffic.
    }

    /**
     * Explicitly called by Server Cron Jobs (e.g. Laravel Scheduler)
     * Bypasses the 60 second web throttle because Cron handles its own scheduling.
     */
    public static function sendCronHeartbeat()
    {
        if (!self::$apiKey) return;
        return self::sendHeartbeatPayload('server_cron');
    }

    private static function sendHeartbeatPayload($source)
    {
        $payload = [
            'app_name' => self::$appName,
            'environment' => self::$environment,
            'started_at' => self::$startTime,
            'source' => $source
        ];
        self::$heartbeatDeliveryOK = self::sendAsyncPayload(self::auxiliaryEndpoint('/heartbeat'), $payload);
        return self::$heartbeatDeliveryOK;
    }

    public static function registerDeployment($version = "unknown")
    {
        if (!self::$apiKey) return;

        $payload = [
            'version' => $version,
            'environment' => self::$environment
        ];

        $deploymentUrl = self::auxiliaryEndpoint('/deployment');

        self::sendAsyncPayload($deploymentUrl, $payload);
    }

    private static function runSecurityEngine()
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        if (!empty(self::$wafConfig['trustProxyHeaders'])) {
            $ip = trim(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $ip)[0]);
        }
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $cfCountry = $_SERVER['HTTP_CF_IPCOUNTRY'] ?? $_SERVER['HTTP_X_VERCEL_IP_COUNTRY'] ?? null;
        $contentLength = isset($_SERVER['CONTENT_LENGTH']) ? (int)$_SERVER['CONTENT_LENGTH'] : 0;

        $waf = self::$wafConfig;
        if (empty($waf['trustProxyHeaders'])) $cfCountry = null;

        // Geo-Blocking
        if (!empty($waf['geoBlocking']['blockedCountries']) && $cfCountry && in_array($cfCountry, $waf['geoBlocking']['blockedCountries'])) {
            self::reportThreat('GEO_BLOCKED', $ip, ['country' => $cfCountry, 'action' => $waf['geoBlocking']['action'] === 'drop' ? 'blocked' : 'observed']);
            if ($waf['geoBlocking']['action'] === 'drop') {
                http_response_code(403);
                die("Access Denied from your Region");
            }
        }

        // Method Tampering
        $allowedMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'];
        if ($waf['methodTampering']['action'] === 'drop' && !in_array($method, $allowedMethods)) {
            self::reportThreat('METHOD_TAMPERING', $ip, ['action' => 'blocked']);
            if ($waf['methodTampering']['action'] === 'drop') {
                http_response_code(405);
                die("Method Not Allowed");
            }
        }

        // Malicious Scanners
        if ($waf['maliciousScanners']['action'] === 'drop' && preg_match('/(sqlmap|nikto|masscan|zmap|nmap)/i', $ua)) {
            self::reportThreat('MALICIOUS_SCANNER', $ip, ['action' => 'blocked']);
            if ($waf['maliciousScanners']['action'] === 'drop') {
                http_response_code(403);
                die("Forbidden Scanner");
            }
        }

        // Payload Overflow
        if ($waf['payloadOverflow']['action'] === 'drop' && $contentLength > $waf['payloadOverflow']['maxPayloadSize']) {
            self::reportThreat('PAYLOAD_OVERFLOW', $ip, ['action' => 'blocked']);
            if ($waf['payloadOverflow']['action'] === 'drop') {
                http_response_code(413);
                die("Payload Too Large");
            }
        }

        // Path Traversal
        if ($waf['pathTraversal']['action'] === 'drop' && preg_match('/(?:\.\.\/|\.\.\\\|%2e%2e%2f|%2e%2e%5c)/i', $uri)) {
            self::reportThreat('PATH_TRAVERSAL', $ip, ['action' => 'blocked']);
            if ($waf['pathTraversal']['action'] === 'drop') {
                http_response_code(403);
                die("Forbidden Path");
            }
        }

        // Honeypot
        $honeypots = ['/wp-admin', '/wp-login.php', '/.env', '/config.php', '/.git/config'];
        if (in_array(explode('?', $uri)[0], $honeypots)) {
            $action = $waf['honeypot']['action'] ?? 'report';
            self::reportThreat('HONEYPOT_ACCESS', $ip, ['action' => $action === 'drop' ? 'blocked' : 'observed']);
            if ($action === 'drop') {
                http_response_code(403);
                die('Access denied by configured path policy');
            }
        }

        // SQLi & XSS Inspection
        $sqliRegex = '/\bUNION\s+(?:ALL\s+)?SELECT\b/i';
        $xssRegex = "/(?:<|%3C)script[\s\S]*?(?:>|%3E)|(?:<|%3C)[\s\S]*?(?:on[a-z]+\s*=)(?:>|%3E)/i";

        $inspectedUri = rawurldecode($uri);
        if (preg_match($sqliRegex, $inspectedUri)) {
            self::reportThreat('SQL_INJECTION', $ip, ['action' => $waf['sqli']['action'] === 'drop' ? 'blocked' : 'observed']);
            if ($waf['sqli']['action'] === 'drop') {
                http_response_code(403);
                die("Desicon Seal WAF: Request blocked by configured policy.");
            }
        } elseif (preg_match($xssRegex, $inspectedUri)) {
            self::reportThreat('XSS_ATTACK', $ip, ['action' => $waf['xss']['action'] === 'drop' ? 'blocked' : 'observed']);
            if ($waf['xss']['action'] === 'drop') {
                http_response_code(403);
                die("Desicon Seal WAF: Request blocked by configured policy.");
            }
        }

        // Fast payload check (POST body)
        if ($contentLength > 0 && $contentLength < 100000) {
            $body = file_get_contents('php://input');
            if ($body) {
                if (preg_match($sqliRegex, $body)) {
                    self::reportThreat('SQL_INJECTION', $ip, ['action' => $waf['sqli']['action'] === 'drop' ? 'blocked' : 'observed']);
                    if ($waf['sqli']['action'] === 'drop') {
                http_response_code(403);
                die("Desicon Seal WAF: Request blocked by configured policy.");
            }
                }
                elseif (preg_match($xssRegex, $body)) {
                    self::reportThreat('XSS_ATTACK', $ip, ['action' => $waf['xss']['action'] === 'drop' ? 'blocked' : 'observed']);
                    if ($waf['xss']['action'] === 'drop') {
                http_response_code(403);
                die("Desicon Seal WAF: Request blocked by configured policy.");
            }
                }
            }
        }
    }

    private static function reportThreat($threatType, $ip, $details = [])
    {
        if (!self::$apiKey) return;

        $payload = [
            'app_name' => self::$appName,
            'environment' => self::$environment,
            'ip_address' => $ip,
            'threat_type' => $threatType,
            'context' => array_merge([
                'method' => $_SERVER['REQUEST_METHOD'] ?? '',
                'path_hash' => hash('sha256', explode('?', $_SERVER['REQUEST_URI'] ?? '')[0]),
                'action' => 'observed',
            ], $details)
        ];

        // Hacky way to inject /threat into endpoint
        $endpoint = self::auxiliaryEndpoint('/threat');
        self::sendAsyncPayload($endpoint, $payload);
    }

    public static function handleException($exception)
    {
        self::dispatchError(
            get_class($exception),
            $exception->getMessage(),
            $exception->getTraceAsString(),
            $exception->getFile(),
            $exception->getLine()
        );
    }

    public static function handleError($errno, $errstr, $errfile, $errline)
    {
        // Don't catch suppressed errors
        if (!(error_reporting() & $errno)) return false;

        $errorType = "PHP Error [$errno]";
        self::dispatchError($errorType, $errstr, "No stack trace for PHP errors", $errfile, $errline);
        return false;
    }

    public static function handleFatalError()
    {
        $error = error_get_last();
        if ($error && in_array($error['type'], [E_ERROR, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR, E_RECOVERABLE_ERROR, E_CORE_WARNING, E_COMPILE_WARNING, E_PARSE])) {
            self::dispatchError("Fatal Error", $error['message'], "Fatal crash during execution.", $error['file'], $error['line']);
        }
    }

    private static function dispatchError($type, $message, $stackTrace, $file, $line)
    {
        if (!self::$apiKey) return;

        $codeContext = self::extractContext($file, $line);

        $payload = [
            'app_name' => self::$appName,
            'environment' => self::$environment,
            'error_type' => $type,
            'error_message' => $message,
            'stack_trace' => $stackTrace,
            'code_context' => $codeContext
        ];

        self::sendAsyncPayload(self::$endpoint, $payload);
    }

    private static function extractContext($file, $line)
    {
        if (!file_exists($file) || !is_readable($file)) {
            return "Could not read local file context.";
        }

        $lines = file($file);
        $start = max(0, $line - 10);
        $end = min(count($lines), $line + 10);
        
        $context = "";
        for ($i = $start; $i < $end; $i++) {
            $prefix = ($i == $line - 1) ? ">> " : "   ";
            $context .= $prefix . ($i + 1) . ": " . $lines[$i];
        }

        return $context;
    }

    /**
     * Bounded synchronous cURL delivery. This may add up to two seconds to a request.
     */
    private static function auxiliaryEndpoint($suffix)
    {
        return str_replace('/sandbox/ingest', '/ingest', rtrim(self::$endpoint, '/')) . $suffix;
    }

    private static function sendAsyncPayload($url, $payload)
    {
        $ch = curl_init($url);
        $jsonData = json_encode($payload);

        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
        if ($jsonData !== 'null') {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $jsonData);
        }
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $headers = [
            'X-API-Key: ' . self::$apiKey
        ];
        
        if ($jsonData !== 'null') {
            $headers[] = 'Content-Type: application/json';
            $headers[] = 'Content-Length: ' . strlen($jsonData);
        }

        if (self::$signingSecret) {
            $timestamp = time();
            $payloadStr = $jsonData !== 'null' ? $jsonData : '';
            $signature = hash_hmac('sha256', $timestamp . '.' . $payloadStr, self::$signingSecret);
            $headers[] = 'X-Seal-Timestamp: ' . $timestamp;
            $headers[] = 'X-Seal-Signature: ' . $signature;
        }

        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        
        // Use full seconds instead of MS for older cPanel versions
        curl_setopt($ch, CURLOPT_TIMEOUT, 2); 
        
        // Require a valid server certificate and hostname.
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);

        curl_setopt($ch, CURLOPT_NOSIGNAL, 1);

        $result = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($result === false || $status < 200 || $status >= 300) return false;
        if (substr($url, -10) === '/heartbeat') {
            $ack = json_decode($result, true);
            return is_array($ack) && ($ack['status'] ?? null) === 'ok';
        }
        return true;
    }
}
