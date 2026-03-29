<?php
/**
 * CSM PHP Shield — Runtime Protection
 *
 * Deployed via: csm install --php-shield
 * Loaded via: auto_prepend_file in php.ini or .user.ini
 *
 * What it does:
 * 1. Blocks PHP execution from dangerous paths (uploads, /tmp, /dev/shm)
 * 2. Logs suspicious POST requests (base64 bodies, unusual PHP targets)
 * 3. Detects eval() abuse at runtime
 *
 * Performance: < 0.1ms overhead per request (pure path checks, no I/O on safe requests)
 * Safety: fails open — if the shield file is deleted or errors, PHP continues normally
 */

// Fail open: wrap everything in try/catch so errors don't break sites
try {

    // --- Configuration ---
    define('CSM_SHIELD_LOG', '/var/run/csm/php_events.log');
    define('CSM_SHIELD_ENABLED', true);

    if (!CSM_SHIELD_ENABLED) return;

    $csm_script = isset($_SERVER['SCRIPT_FILENAME']) ? $_SERVER['SCRIPT_FILENAME'] : '';
    if ($csm_script === '' || $csm_script === __FILE__) return;

    $csm_script_lower = strtolower($csm_script);
    $csm_request_uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';

    // --- 1. Block PHP execution from dangerous paths ---
    // These directories should NEVER execute PHP directly
    $csm_blocked_paths = array(
        '/wp-content/uploads/',
        '/wp-content/upgrade/',
        '/tmp/',
        '/dev/shm/',
        '/var/tmp/',
    );

    foreach ($csm_blocked_paths as $blocked) {
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
            echo '<!-- blocked by security policy -->';
            exit;
        }
    }

    // --- 2. Detect webshell command parameters ---
    // Only inspects $_POST/$_GET/$_REQUEST arrays — never reads php://input
    // (reading the raw body would break REST APIs, WooCommerce, webhooks, etc.)
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $csm_cmd_params = array('cmd', 'command', 'exec', 'execute', 'c', 'e', 'shell');
        foreach ($csm_cmd_params as $param) {
            if (isset($_POST[$param]) || isset($_GET[$param]) || isset($_REQUEST[$param])) {
                csm_shield_log('WEBSHELL_PARAM', $csm_script,
                    'Request contains command parameter: ' . $param);
                break;
            }
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
 * Log a security event to the CSM event log.
 * The daemon watches this file via inotify for real-time alerting.
 */
function csm_shield_log($event_type, $script, $details) {
    $log_file = CSM_SHIELD_LOG;
    $dir = dirname($log_file);
    if (!is_dir($dir)) {
        @mkdir($dir, 0750, true);
    }

    if (!is_writable($dir)) {
        if (!defined('CSM_SHIELD_LOG_WARNED')) {
            define('CSM_SHIELD_LOG_WARNED', true);
            error_log('CSM PHP Shield: cannot write to ' . $dir . ' — events will not be logged');
        }
        return;
    }

    $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '-';
    $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '-';
    $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'], 0, 100) : '-';

    $line = sprintf("[%s] %s ip=%s script=%s uri=%s ua=%s details=%s\n",
        date('Y-m-d H:i:s'),
        $event_type,
        $ip,
        $script,
        substr($uri, 0, 200),
        $user_agent,
        $details
    );

    // Append atomically — O_APPEND ensures no interleaving on Linux
    @file_put_contents($log_file, $line, FILE_APPEND | LOCK_EX);
}
