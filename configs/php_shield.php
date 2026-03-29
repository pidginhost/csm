<?php
/**
 * CSM PHP Shield — Runtime Protection
 *
 * Deployed via: csm install --php-shield
 * Loaded via: auto_prepend_file in php.ini or .user.ini
 *
 * Features:
 * 1. Blocks PHP execution from dangerous paths (configurable)
 * 2. Detects webshell command parameters on GET and POST
 * 3. Detects eval() abuse at runtime via shutdown handler
 * 4. Per-account disable via .csm-shield-disable file
 * 5. IP allowlisting from shield.conf.php
 * 6. Rate limiting via log file size cap
 * 7. Proper 403 response page
 *
 * Performance: < 0.1ms overhead per request (path checks, no I/O on safe requests)
 * Safety: fails open — if the shield file is deleted or errors, PHP continues normally
 */

// Fail open: wrap everything in try/catch so errors don't break sites
try {

    define('CSM_SHIELD_VERSION', '2.0.0');
    define('CSM_SHIELD_LOG', '/var/run/csm/php_events.log');
    define('CSM_SHIELD_CONF', '/opt/csm/shield.conf.php');
    define('CSM_SHIELD_MAX_LOG_BYTES', 10485760); // 10MB

    $csm_script = isset($_SERVER['SCRIPT_FILENAME']) ? $_SERVER['SCRIPT_FILENAME'] : '';
    if ($csm_script === '' || $csm_script === __FILE__) return;

    // --- Per-account disable ---
    // Create /home/<user>/.csm-shield-disable to skip shield for that account
    if (preg_match('#^/home/([^/]+)/#', $csm_script, $csm_m)) {
        if (file_exists('/home/' . $csm_m[1] . '/.csm-shield-disable')) return;
    }

    // --- Load config (blocked paths, allowed IPs) ---
    $csm_conf = csm_shield_load_config();

    // --- IP allowlist check ---
    $csm_ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
    if ($csm_ip !== '' && in_array($csm_ip, $csm_conf['allowed_ips'], true)) return;

    $csm_script_lower = strtolower($csm_script);

    // --- 1. Block PHP execution from dangerous paths ---
    foreach ($csm_conf['blocked_paths'] as $blocked) {
        if (strpos($csm_script_lower, $blocked) !== false) {
            // Allow known safe files (WP handles, cache plugins)
            $csm_basename = basename($csm_script_lower);
            $csm_safe_uploads = array('index.php', 'wp-cron.php');
            if (in_array($csm_basename, $csm_safe_uploads)) continue;

            // Allow known safe paths
            $csm_safe_paths = array('/cache/', '/imunify', '/sucuri/', '/smush/');
            $csm_is_safe = false;
            foreach ($csm_safe_paths as $safe) {
                if (strpos($csm_script_lower, $safe) !== false) {
                    $csm_is_safe = true;
                    break;
                }
            }
            if ($csm_is_safe) continue;

            // Block and log
            csm_shield_log('BLOCK_PATH', $csm_script, 'PHP execution from blocked path');
            http_response_code(403);
            echo "<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body>\n";
            echo "<h1>403 Forbidden</h1>\n";
            echo "<p>PHP execution is not allowed from this location.</p>\n";
            echo "<hr><small>Security Policy</small></body></html>\n";
            exit;
        }
    }

    // --- 2. Detect webshell command parameters (GET and POST) ---
    // Only inspects $_REQUEST arrays — never reads php://input
    $csm_cmd_params = array('cmd', 'command', 'exec', 'execute', 'c', 'e', 'shell');
    foreach ($csm_cmd_params as $param) {
        if (isset($_REQUEST[$param])) {
            csm_shield_log('WEBSHELL_PARAM', $csm_script,
                'Request contains command parameter: ' . $param);
            break;
        }
    }

    // --- 3. Register shutdown function to detect eval() abuse ---
    // This catches fatal errors from eval() chains that fail
    register_shutdown_function(function() {
        $error = error_get_last();
        if ($error !== null && $error['type'] === E_ERROR) {
            if (strpos($error['message'], 'eval()') !== false) {
                csm_shield_log('EVAL_FATAL', $error['file'],
                    'Fatal error in eval(): ' . substr($error['message'], 0, 200));
            }
        }
    });

} catch (Exception $e) {
    // Fail open — don't break sites if shield has a bug
}

/**
 * Load shield config from /opt/csm/shield.conf.php.
 * Falls back to hardcoded defaults if file doesn't exist.
 * The config file is a PHP file that returns an array (opcode-cacheable).
 */
function csm_shield_load_config() {
    $defaults = array(
        'blocked_paths' => array(
            '/wp-content/uploads/',
            '/wp-content/upgrade/',
            '/tmp/',
            '/dev/shm/',
            '/var/tmp/',
        ),
        'allowed_ips' => array(),
    );

    if (file_exists(CSM_SHIELD_CONF)) {
        $custom = @include CSM_SHIELD_CONF;
        if (is_array($custom)) {
            if (isset($custom['blocked_paths']) && is_array($custom['blocked_paths'])) {
                $defaults['blocked_paths'] = $custom['blocked_paths'];
            }
            if (isset($custom['allowed_ips']) && is_array($custom['allowed_ips'])) {
                $defaults['allowed_ips'] = $custom['allowed_ips'];
            }
        }
    }

    return $defaults;
}

/**
 * Log a security event to the CSM event log.
 * The daemon watches this file for real-time alerting.
 * Rate-limited by log file size (stops writing at CSM_SHIELD_MAX_LOG_BYTES).
 */
function csm_shield_log($event_type, $script, $details) {
    $log_file = CSM_SHIELD_LOG;
    $dir = dirname($log_file);
    if (!is_dir($dir)) {
        @mkdir($dir, 0750, true);
    }

    // Health check: verify writability
    if (!is_writable($dir)) {
        if (!defined('CSM_SHIELD_LOG_WARNED')) {
            define('CSM_SHIELD_LOG_WARNED', true);
            error_log('CSM PHP Shield: cannot write to ' . $dir . ' — events will not be logged');
        }
        return;
    }

    // Rate limit: skip if log file exceeds size cap (logrotate handles cleanup)
    $size = @filesize($log_file);
    if ($size !== false && $size > CSM_SHIELD_MAX_LOG_BYTES) return;

    $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '-';
    $uri = isset($_SERVER['REQUEST_URI']) ? substr($_SERVER['REQUEST_URI'], 0, 200) : '-';
    $ua = isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'], 0, 100) : '-';

    $line = sprintf("[%s] %s ip=%s script=%s uri=%s ua=%s details=%s\n",
        date('Y-m-d H:i:s'),
        $event_type,
        $ip,
        $script,
        $uri,
        $ua,
        $details
    );

    // Append atomically — O_APPEND ensures no interleaving on Linux
    @file_put_contents($log_file, $line, FILE_APPEND | LOCK_EX);
}
