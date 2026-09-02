<?php
/**
 * CSM PHP Shield -- Runtime Protection
 *
 * Deployed via: csm install --php-shield
 * Loaded via: auto_prepend_file in php.ini or .user.ini
 *
 * Features:
 * 1. Blocks PHP execution from dangerous paths (uploads, tmp)
 * 2. Blocks directly-executed wp-content scripts whose source matches a
 *    webshell signature (exec sink over request input, or packed eval loader)
 * 3. Blocks command parameters backed by an exec sink in an inspected script
 * 4. Detects eval() abuse at runtime via shutdown handler
 * 5. Per-account disable via .csm-shield-disable file
 * 6. IP allowlisting from shield.conf.php
 * 7. Cross-account event isolation via a daemon-owned datagram socket
 *
 * This reference copy is kept in sync with the deployed shield embedded in
 * cmd/csm/installer.go (shieldContent). Behaviour must match; only the naming
 * and documentation differ.
 *
 * Safety: fails open -- if the shield file is deleted or errors, PHP continues.
 */

// Fail open: wrap everything in try/catch so errors don't break sites
try {

    define('CSM_SHIELD_VERSION', '2.1.0');
    define('CSM_SHIELD_SOCKET', '/var/log/csm-php-shield/events.sock');
    define('CSM_SHIELD_CONF', '/opt/csm/shield.conf.php');

    $csm_script = isset($_SERVER['SCRIPT_FILENAME']) ? $_SERVER['SCRIPT_FILENAME'] : '';
    if ($csm_script === '' || $csm_script === __FILE__) return;

    // --- Per-account disable ---
    if (preg_match('#^/home/([^/]+)/#', $csm_script, $csm_m)) {
        if (file_exists('/home/' . $csm_m[1] . '/.csm-shield-disable')) return;
    }

    $csm_conf = csm_shield_load_config();

    // --- IP allowlist (plain IPs and CIDR) ---
    $csm_ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
    if ($csm_ip !== '' && csm_shield_ip_allowed($csm_ip, $csm_conf['allowed_ips'])) return;

    $csm_script_lower = strtolower($csm_script);
    $csm_src = null;
    $csm_code = null;

    // --- 1. Block PHP execution from dangerous paths (uploads/tmp) ---
    // No path is allowlisted here: an attacker who learns a "safe" prefix drops
    // the shell there. Cache/plugin/theme directories are covered by content
    // inspection below instead of a blanket path skip.
    foreach ($csm_conf['blocked_paths'] as $blocked) {
        if (strpos($csm_script_lower, $blocked) !== false) {
            csm_shield_log('BLOCK_PATH', $csm_script, 'PHP execution from blocked path');
            csm_shield_deny();
        }
    }

    // --- 2. Content-based webshell block for direct wp-content script hits ---
    // A normal request executes the document-root index.php, outside
    // wp-content. Any entry script under wp-content is a direct hit.
    if (strpos($csm_script_lower, '/wp-content/') !== false) {
        $csm_src = @file_get_contents($csm_script, false, null, 0, 65536);
        if ($csm_src !== false) $csm_code = csm_shield_code_only($csm_src);
        if ($csm_code !== null && csm_shield_is_webshell($csm_code)) {
            csm_shield_log('BLOCK_WEBSHELL', $csm_script, 'Webshell signature in directly-executed script');
            csm_shield_deny();
        }
    }

    // --- 3. Command parameter backed by an exec sink in the inspected script ---
    // A named parameter like cmd= or shell= is a webshell convention on its
    // own. The single letters are not: WordPress core's own load-styles.php
    // and load-scripts.php take c=0 as a compression flag, so logging every
    // one of those buried real probes under ordinary admin traffic. For the
    // weak names the value has to look like a command before it is worth
    // recording. Blocking is unchanged and still keyed on the exec sink.
    $csm_cmd_params = array('cmd', 'command', 'exec', 'execute', 'shell');
    $csm_weak_cmd_params = array('c', 'e');
    foreach (array_merge($csm_cmd_params, $csm_weak_cmd_params) as $param) {
        if (isset($_REQUEST[$param])) {
            if (in_array($param, $csm_cmd_params, true) || csm_shield_is_command_value($_REQUEST[$param])) {
                csm_shield_log('WEBSHELL_PARAM', $csm_script, 'Request contains command parameter: ' . $param);
            }
            if ($csm_code !== null && csm_shield_has_exec_sink($csm_code)) {
                csm_shield_log('BLOCK_WEBSHELL', $csm_script, 'Command parameter with exec sink: ' . $param);
                csm_shield_deny();
            }
            break;
        }
    }

    // --- 4. Shutdown handler to detect eval() chains that fatal ---
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
    // Fail open -- don't break sites if shield has a bug
}

/**
 * Remove comments and string contents before signature matching so help text,
 * examples, and inert literals cannot turn a legitimate endpoint into a hit.
 */
function csm_shield_code_only($src) {
    if (!function_exists('token_get_all')) return $src;

    $out = '';
    $quoted = false;
    $heredoc = false;
    foreach (token_get_all($src) as $token) {
        if (is_array($token)) {
            $id = $token[0];
            if ($id === T_START_HEREDOC) {
                $heredoc = true;
                $out .= ' ';
                continue;
            }
            if ($id === T_END_HEREDOC) {
                $heredoc = false;
                $out .= ' ';
                continue;
            }
            if ($quoted || $heredoc
                || $id === T_COMMENT
                || $id === T_DOC_COMMENT
                || $id === T_CONSTANT_ENCAPSED_STRING
                || $id === T_ENCAPSED_AND_WHITESPACE
                || $id === T_INLINE_HTML) {
                $out .= ' ';
                continue;
            }
            $out .= $token[1];
        } else {
            if ($token === '"') {
                $quoted = !$quoted;
                $out .= ' ';
                continue;
            }
            if (!$quoted && !$heredoc) $out .= $token;
        }
    }
    return $out;
}

/**
 * True if a request value looks like a command rather than an ordinary
 * argument. Used only for the single-letter parameter names, which collide
 * with legitimate application parameters (WordPress core's own c=0).
 *
 * A shell command needs a separator, a path, or the name of a binary. A bare
 * number or word is none of those.
 */
function csm_shield_is_command_value($value, $depth = 0) {
    if (is_array($value)) {
        foreach ($value as $item) {
            if (csm_shield_is_command_value($item, $depth)) return true;
        }
        return false;
    }
    if (!is_string($value)) return false;
    $v = trim($value);
    if ($v === '') return false;
    // No ordinary application flag is this long. Treating an oversized value as
    // uninteresting would hand an attacker a way to stay silent by padding.
    if (strlen($v) > 512) return true;
    // Shell metacharacters, or anything the shell would read as more than one word.
    if (preg_match('/[;|&\x60$(){}<>\\\\\s\'"]/', $v)) return true;
    // A path, absolute or traversing.
    if (strpos($v, '/') !== false || strpos($v, '..') !== false) return true;
    // A bare binary name.
    if (preg_match('/^(?:ls|id|pwd|whoami|uname|cat|head|tail|wget|curl|nc|ncat|socat|telnet|ftp|tftp|sh|bash|zsh|dash|python[0-9.]*|perl|ruby|node|php|awk|sed|env|base64|xxd|openssl|busybox|chmod|chown|rm|mv|cp|kill|ps|netstat|ifconfig|ipconfig|dir|type|systeminfo|net|tasklist)$/i', $v)) return true;
    // A packed webshell builds its sink name at runtime, so the source scan
    // finds nothing and this event is the only trace it leaves. Those hand the
    // command in base64, so look one level through it.
    if ($depth === 0 && preg_match('/^[A-Za-z0-9+\/_=-]{4,}$/', $v)) {
        // base64url swaps +/ for -_; a packed shell translates it back
        // before decoding, so normalise before the strict decode.
        $decoded = base64_decode(strtr($v, '-_', '+/'), true);
        if (is_string($decoded) && $decoded !== '' && $decoded === preg_replace('/[^\x20-\x7e]/', '', $decoded)) {
            return csm_shield_is_command_value($decoded, 1);
        }
    }
    return false;
}

/**
 * True if the script's own source calls a command-execution function.
 * Token inspection separates global calls from methods, static methods,
 * constructors, and function declarations with the same names.
 */
function csm_shield_has_exec_sink($src) {
    $sinks = array_fill_keys(array(
        'system',
        'passthru',
        'shell_exec',
        'proc_open',
        'popen',
        'exec',
    ), true);
    if (!function_exists('token_get_all')) {
        $src = preg_replace(
            '/(?:->|::)\s*(?:system|passthru|shell_exec|proc_open|popen|exec)\s*\(/i',
            '',
            $src
        );
        return (bool) preg_match(
            '/(?<![\w>:\\\\])\\\\?(?:system|passthru|shell_exec|proc_open|popen|exec)\s*\(/i',
            $src
        );
    }

    $tokens = token_get_all($src);
    $count = count($tokens);
    for ($i = 0; $i < $count; $i++) {
        $token = $tokens[$i];
        if (!is_array($token)) continue;

        $id = $token[0];
        $name = null;
        $qualified = false;
        if ($id === T_STRING) {
            $name = strtolower($token[1]);
        } elseif (defined('T_NAME_FULLY_QUALIFIED')
            && $id === constant('T_NAME_FULLY_QUALIFIED')) {
            $name = strtolower(ltrim($token[1], '\\'));
            $qualified = true;
            if (strpos($name, '\\') !== false) continue;
        }
        if ($name === null || !isset($sinks[$name])) continue;

        $previous = null;
        $previous_index = -1;
        for ($j = $i - 1; $j >= 0; $j--) {
            if (is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) continue;
            $previous = $tokens[$j];
            $previous_index = $j;
            break;
        }
        if (!$qualified && is_array($previous)) {
            if ($previous[0] === T_OBJECT_OPERATOR
                || $previous[0] === T_DOUBLE_COLON
                || $previous[0] === T_FUNCTION
                || $previous[0] === T_NEW) {
                continue;
            }
            if (defined('T_NULLSAFE_OBJECT_OPERATOR')
                && $previous[0] === constant('T_NULLSAFE_OBJECT_OPERATOR')) {
                continue;
            }
            if ($previous[0] === T_NS_SEPARATOR) {
                $before_separator = null;
                for ($j = $previous_index - 1; $j >= 0; $j--) {
                    if (is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) continue;
                    $before_separator = $tokens[$j];
                    break;
                }
                if (is_array($before_separator)
                    && ($before_separator[0] === T_STRING
                        || $before_separator[0] === T_NAMESPACE)) {
                    continue;
                }
            }
        }

        for ($j = $i + 1; $j < $count; $j++) {
            if (is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) continue;
            if ($tokens[$j] === '(') return true;
            break;
        }
    }
    return false;
}

/**
 * True if the script source looks like a webshell: an exec sink applied in a
 * script that reads request input, or an eval() fed by a decode/inflate wrapper.
 */
function csm_shield_is_webshell($src) {
    if (csm_shield_has_exec_sink($src) && preg_match('/\$_(?:REQUEST|GET|POST|COOKIE|SERVER)\b/', $src)) {
        return true;
    }
    if (preg_match('/\beval\s*\(/i', $src)
        && preg_match('/(?:gzinflate|gzuncompress|gzdecode|str_rot13|base64_decode|openssl_decrypt)\s*\(/i', $src)) {
        return true;
    }
    return false;
}

/**
 * Emit a 403 and stop. Shared by every block path.
 */
function csm_shield_deny() {
    http_response_code(403);
    echo "<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body>\n";
    echo "<h1>403 Forbidden</h1>\n";
    echo "<p>PHP execution is not allowed from this location.</p>\n";
    echo "<hr><small>Security Policy</small></body></html>\n";
    exit;
}

/**
 * Check if an IP matches any entry in the allowlist (plain IP or CIDR).
 */
function csm_shield_ip_allowed($ip, $allowlist) {
    $ip_long = ip2long($ip);
    if ($ip_long === false) return false;

    foreach ($allowlist as $entry) {
        if (strpos($entry, '/') !== false) {
            list($subnet, $bits) = explode('/', $entry, 2);
            $subnet_long = ip2long($subnet);
            $mask = -1 << (32 - (int)$bits);
            if (($ip_long & $mask) === ($subnet_long & $mask)) return true;
        } else {
            if ($ip === $entry) return true;
        }
    }
    return false;
}

/**
 * Load shield config from /opt/csm/shield.conf.php.
 * Falls back to hardcoded defaults if file doesn't exist.
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
 * Send one bounded datagram to the root daemon. The shared CageFS directory is
 * not tenant-writable; only the socket accepts writes, and the archive remains
 * root-only.
 */
function csm_shield_log($event_type, $script, $details) {
    $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '-';
    $uri = isset($_SERVER['REQUEST_URI']) ? substr($_SERVER['REQUEST_URI'], 0, 200) : '-';
    $ua = isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'], 0, 100) : '-';
    $clean = function($value) { return str_replace(array("\r", "\n"), ' ', $value); };

    $line = sprintf("[%s] %s ip=%s script=%s uri=%s ua=%s details=%s\n",
        date('Y-m-d H:i:s'),
        $clean($event_type),
        $clean($ip),
        $clean($script),
        $clean($uri),
        $clean($ua),
        $clean($details)
    );

    $socket = @stream_socket_client('udg://' . CSM_SHIELD_SOCKET, $errno, $errstr, 0.05);
    if ($socket === false) {
        if (!defined('CSM_SHIELD_LOG_WARNED')) {
            define('CSM_SHIELD_LOG_WARNED', true);
            error_log('CSM PHP Shield: event socket unavailable');
        }
        return;
    }
    // A full daemon receive queue must never stall another tenant's request.
    @stream_set_blocking($socket, false);
    $sent = @fwrite($socket, $line);
    @fclose($socket);
    if ($sent !== strlen($line) && !defined('CSM_SHIELD_LOG_WARNED')) {
        define('CSM_SHIELD_LOG_WARNED', true);
        error_log('CSM PHP Shield: event socket write failed');
    }
}
