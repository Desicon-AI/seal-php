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

    // Default WAF Config
    private static $defaultWaf = [
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
        } else {
            // Ping the backend to auto-resolve old errors on startup
            $pingUrl = self::$endpoint . '/ping';
            // Simple fire-and-forget for ping
            self::sendAsyncPayload($pingUrl, null);
        }

        // 1. Hook PHP Error & Exception Handlers
        set_exception_handler([__CLASS__, 'handleException']);
        set_error_handler([__CLASS__, 'handleError']);
        register_shutdown_function([__CLASS__, 'handleFatalError']);

        // 2. Execute Zero-Latency WAF
        self::runSecurityEngine();

        // 3. Traffic-Triggered Heartbeat (Zero Server Setup)
        self::sendHeartbeatIfRequired();
    }

    /**
     * "Poor Man's Cron" - Uses standard web traffic to trigger the heartbeat.
     * Prevents the need for server cron jobs.
     */
    private static function sendHeartbeatIfRequired()
    {
        if (!self::$apiKey) return;

        $tempFile = sys_get_temp_dir() . '/seal_last_heartbeat_' . md5(self::$appName) . '.txt';
        $now = time();

        // If file doesn't exist, or it has been > 60 seconds since last heartbeat
        if (!file_exists($tempFile) || ($now - filemtime($tempFile)) > 60) {
            // Update the modified time immediately to prevent race conditions from other concurrent requests
            touch($tempFile);
            self::sendHeartbeatPayload('web_traffic');
        }
    }

    /**
     * Explicitly called by Server Cron Jobs (e.g. Laravel Scheduler)
     * Bypasses the 60 second web throttle because Cron handles its own scheduling.
     */
    public static function sendCronHeartbeat()
    {
        if (!self::$apiKey) return;
        self::sendHeartbeatPayload('server_cron');
    }

    private static function sendHeartbeatPayload($source)
    {
        $payload = [
            'app_name' => self::$appName,
            'environment' => self::$environment,
            'started_at' => self::$startTime,
            'source' => $source
        ];
        self::sendAsyncPayload(self::$endpoint . '/heartbeat', $payload);
    }

    public static function registerDeployment($version = "unknown")
    {
        if (!self::$apiKey) return;

        $payload = [
            'version' => $version,
            'environment' => self::$environment
        ];

        // Replace /ingest with /deployment in URL
        $deploymentUrl = str_replace('/ingest', '/deployment', self::$endpoint);
        $deploymentUrl = str_replace('/api/v1/sandbox/deployment', '/api/v1/deployment', $deploymentUrl);

        self::sendAsyncPayload($deploymentUrl, $payload);
    }

    private static function runSecurityEngine()
    {
        $ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $cfCountry = $_SERVER['HTTP_CF_IPCOUNTRY'] ?? $_SERVER['HTTP_X_VERCEL_IP_COUNTRY'] ?? null;
        $contentLength = isset($_SERVER['CONTENT_LENGTH']) ? (int)$_SERVER['CONTENT_LENGTH'] : 0;

        $waf = self::$wafConfig;

        // Geo-Blocking
        if (!empty($waf['geoBlocking']['blockedCountries']) && $cfCountry && in_array($cfCountry, $waf['geoBlocking']['blockedCountries'])) {
            self::reportThreat('GEO_BLOCKED', $ip, ['country' => $cfCountry]);
            if ($waf['geoBlocking']['action'] === 'drop') {
                http_response_code(403);
                die("Access Denied from your Region");
            }
        }

        // Method Tampering
        $allowedMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'];
        if ($waf['methodTampering']['action'] === 'drop' && !in_array($method, $allowedMethods)) {
            self::reportThreat('METHOD_TAMPERING', $ip, ['method' => $method]);
            if ($waf['methodTampering']['action'] === 'drop') {
                http_response_code(405);
                die("Method Not Allowed");
            }
        }

        // Malicious Scanners
        if ($waf['maliciousScanners']['action'] === 'drop' && preg_match('/(sqlmap|nikto|masscan|zmap|nmap|python-requests|curl|wget)/i', $ua)) {
            self::reportThreat('MALICIOUS_SCANNER', $ip, ['user_agent' => $ua]);
            if ($waf['maliciousScanners']['action'] === 'drop') {
                http_response_code(403);
                die("Forbidden Scanner");
            }
        }

        // Payload Overflow
        if ($waf['payloadOverflow']['action'] === 'drop' && $contentLength > $waf['payloadOverflow']['maxPayloadSize']) {
            self::reportThreat('PAYLOAD_OVERFLOW', $ip, ['content_length' => $contentLength]);
            if ($waf['payloadOverflow']['action'] === 'drop') {
                http_response_code(413);
                die("Payload Too Large");
            }
        }

        // Path Traversal
        if ($waf['pathTraversal']['action'] === 'drop' && preg_match('/(?:\.\.\/|\.\.\\\|%2e%2e%2f|%2e%2e%5c)/i', $uri)) {
            self::reportThreat('PATH_TRAVERSAL', $ip, []);
            if ($waf['pathTraversal']['action'] === 'drop') {
                http_response_code(403);
                die("Forbidden Path");
            }
        }

        // Honeypot
        $honeypots = ['/wp-admin', '/wp-login.php', '/.env', '/config.php', '/.git/config'];
        if (in_array(explode('?', $uri)[0], $honeypots)) {
            self::reportThreat('HONEYPOT_ACCESS', $ip, []);
        }

        // SQLi & XSS Inspection
        $sqliRegex = "/(?:\b(ALTER|CREATE|DELETE|DROP|EXEC(UTE){0,1}|INSERT( +INTO){0,1}|MERGE|SELECT|UPDATE|UNION( +ALL){0,1})\b)|(?:'|%27).*?(?:OR|AND).*?(?:'|%27)|(?:--)/i";
        $xssRegex = "/(?:<|%3C)script[\s\S]*?(?:>|%3E)|(?:<|%3C)[\s\S]*?(?:on[a-z]+\s*=)(?:>|%3E)/i";

        if (preg_match($sqliRegex, $uri)) {
            self::reportThreat('SQL_INJECTION', $ip, []);
        } elseif (preg_match($xssRegex, $uri)) {
            self::reportThreat('XSS_ATTACK', $ip, []);
        }

        // Fast payload check (POST body)
        if ($contentLength > 0 && $contentLength < 100000) {
            $body = file_get_contents('php://input');
            if ($body) {
                if (preg_match($sqliRegex, $body)) self::reportThreat('SQL_INJECTION', $ip, []);
                elseif (preg_match($xssRegex, $body)) self::reportThreat('XSS_ATTACK', $ip, []);
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
                'url' => $_SERVER['REQUEST_URI'] ?? '',
            ], $details)
        ];

        // Hacky way to inject /threat into endpoint
        $endpoint = str_replace('/ingest', '/ingest/threat', self::$endpoint);
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
     * Fire-and-forget cURL request (adds 0 latency to the PHP page load)
     */
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
        
        // Timeout of 100ms. We don't care about the response, we just want to fire it off.
        curl_setopt($ch, CURLOPT_TIMEOUT_MS, 100);
        curl_setopt($ch, CURLOPT_NOSIGNAL, 1);

        curl_exec($ch);
        curl_close($ch);
    }
}
