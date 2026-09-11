#!/usr/bin/env python3
"""Exercise the shipped rules with Apache ModSecurity v2 and PHP on Debian.

Requires apache2, libapache2-mod-security2, libapache2-mod-php and python3.
Run in a disposable Linux environment; no host Apache configuration is used.
"""

import argparse
import http.client
import json
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
WEAK = "litespeed_role=1; litespeed_hash=Ab3Xz9"
STRONG = "litespeed_role=1; litespeed_hash=" + "Ab3Xz9" * 5 + "a1"


def cases():
    for method in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"):
        yield method + " users", method, "/wp-json/wp/v2/users", WEAK, {}, True
        yield method + " public", method, "/shop/", WEAK, {}, method not in ("GET", "HEAD")
        yield method + " fixed hash", method, "/shop/", STRONG, {}, False
        yield method + " fixed hash users", method, "/wp-json/wp/v2/users", STRONG, {}, False
        yield method + " no cookies", method, "/shop/", "", {}, False
    for role in ("%31", "+1", "1.0", "1e0", "%201", "1%20"):
        yield "role " + role, "POST", "/", "litespeed_role=" + role + "; litespeed_hash=Ab3Xz9", {}, True
    for name in ("litespeed.role", "litespeed role", "litespeed[role"):
        yield "role alias " + name, "POST", "/", name + "=1; litespeed_hash=Ab3Xz9", {}, True
    for name in ("litespeed.hash", "litespeed hash", "litespeed[hash"):
        yield "hash alias " + name, "POST", "/", "litespeed_role=1; " + name + "=Ab3Xz9", {}, True
    for value in ("%41b3Xz9", "%41%62%33%58%7a%39", "+123456", "123456.0", "1.23456e5", "1.23456e+5", "1.23456e%2b5", "00000000000000000000000000123456", "%20123456%20"):
        yield "hash " + value, "POST", "/", "litespeed_role=1; litespeed_hash=" + value, {}, True
    for suffix in ("_method=POST", "%5fmethod=POST", ".method=POST", "+_method=POST", "_method=post"):
        yield "query override " + suffix, "GET", "/wp-json/wp/v2/plugins?" + suffix, WEAK, {}, True
    for header in ("X-HTTP-Method-Override", "X_HTTP_Method_Override", "X.HTTP.Method.Override"):
        yield "header override " + header, "GET", "/wp-json/wp/v2/plugins", WEAK, {header: "POST"}, True
    for uri in ("/wp-admin", "/wp-admin?x=1", "/blog/wp-admin/", "/wp-admin/../wp-admin/users.php", "/wp-json/wp/v2/users/me", "/?rest_route=wp/v2/users", "/?rest.route=/wp/v2/users", "/?+rest_route=/wp/v2/users", "/?rest_route=%2Fwp%2Fv2%2Fusers"):
        yield "privileged " + uri, "GET", uri, WEAK, {}, True
    for uri in ("/", "/shop/product/", "/wp-json/wp/v2/posts", "/?next=/wp-admin/", "/?next=/wp-json/wp/v2/users", "/?next=rest_route=/wp/v2/users", "/wp-json/wp/v2/users-guide", "/?rest_route=/wp/v2/users-guide", "/?rest_route=/wp/v2/posts"):
        yield "crawler " + uri, "GET", uri, WEAK, {}, False
    for cookie in ("litespeed_role=1", "litespeed_hash=Ab3Xz9", "other_role=1; litespeed_hash=Ab3Xz9", "litespeed_role=1; other_hash=Ab3Xz9", STRONG):
        yield "unrelated " + cookie, "POST", "/", cookie, {}, False


def request(port, method, uri, cookie, headers):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(method, uri, headers={"Cookie": cookie, **headers})
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--conf", type=Path, default=ROOT / "configs/csm_modsec_custom.conf")
    args = parser.parse_args()
    conf = args.conf.resolve()
    # Parse the complete file before excluding unrelated denies, so a bad
    # directive anywhere still fails the configuration-load gate.
    other_ids = [i for i in re.findall(r"\bid:(\d+)", conf.read_text()) if i not in ("900128", "900129")]
    modules = Path("/usr/lib/apache2/modules")
    php_module = next(modules.glob("libphp*.so"))
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix="csm-modsec-") as tmp:
        base = Path(tmp)
        base.chmod(0o755)
        (base / "index.php").write_text('''<?php
// Mirror the relevant PHP/WordPress coercions, without a database or WordPress
// installation. The integration assertions below pin PHP's real cookie parser.
// LiteSpeed Cache 6.3 router.cls.php::is_role_simulation compares with !=;
// WordPress 6.6.1 WP_User::get_data_by requires is_numeric before casting IDs.
$role = $_COOKIE['litespeed_role'] ?? '';
$hash = $_COOKIE['litespeed_hash'] ?? '';
header('Content-Type: application/json');
echo json_encode([
    'user' => is_numeric($role) ? (int) $role : 0,
    'hash_matches' => $hash == 'Ab3Xz9' || $hash == '123456',
    'method' => strtoupper($_GET['_method'] ?? $_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'] ?? $_SERVER['REQUEST_METHOD']),
]);
''')
        apache_conf = base / "httpd.conf"
        apache_conf.write_text(f'''
ServerRoot "{base}"
ServerName localhost
Listen 127.0.0.1:{port}
PidFile "{base}/httpd.pid"
ErrorLog "{base}/error.log"
LoadModule mpm_prefork_module {modules}/mod_mpm_prefork.so
LoadModule authz_core_module {modules}/mod_authz_core.so
LoadModule rewrite_module {modules}/mod_rewrite.so
LoadModule unique_id_module {modules}/mod_unique_id.so
LoadModule security2_module {modules}/mod_security2.so
LoadModule php_module {php_module}
User www-data
Group www-data
DocumentRoot "{base}"
<Directory "{base}">
    Require all granted
    <Files "index.php">
        SetHandler application/x-httpd-php
    </Files>
</Directory>
RewriteEngine On
RewriteRule ^ /index.php [END]
SecRuleEngine On
SecRequestBodyAccess On
SecAuditEngine Off
SecDataDir /tmp
Include "{conf}"
SecRuleRemoveById {' '.join(other_ids)}
''')
        subprocess.run(["apache2", "-t", "-f", str(apache_conf)], check=True)
        server = subprocess.Popen(["apache2", "-X", "-f", str(apache_conf)])
        failures = []
        try:
            for _ in range(100):
                if server.poll() is not None:
                    raise RuntimeError((base / "error.log").read_text())
                try:
                    request(port, "GET", "/", "", {})
                    break
                except ConnectionRefusedError:
                    time.sleep(0.05)
            else:
                raise RuntimeError("Apache did not start")
            # Verify PHP's real query/header parsing independently of cookies.
            for _, _, uri, _, headers, _ in cases():
                if "_method=" in uri or "%5fmethod=" in uri or ".method=" in uri or "X-HTTP-Method-Override" in headers:
                    status, body = request(port, "GET", uri, "", headers)
                    if status != 200 or json.loads(body)["method"] != "POST":
                        failures.append(f"invalid method override fixture: {uri}, {headers}")
            count = 0
            for name, method, uri, cookie, headers, blocked in cases():
                count += 1
                status, body = request(port, method, uri, cookie, headers)
                if status != (403 if blocked else 200):
                    failures.append(f"{name}: HTTP {status}, expected {'403' if blocked else '200'}")
                # On an allowed public GET, PHP must still interpret these
                # spellings as the same simulation. This catches invented
                # bypass fixtures that the application never accepts.
                if name.startswith(("role ", "hash ", "query override ", "header override ")):
                    # Omit method overrides from this parser-only probe.
                    _, probe = request(port, "GET", "/", cookie, {})
                    parsed = json.loads(probe)
                    if parsed["user"] != 1 or not parsed["hash_matches"]:
                        failures.append(f"{name}: PHP does not accept the simulation fixture: {parsed}")
            if failures:
                print((base / "error.log").read_text()[-5000:])
            for failure in failures:
                print("FAIL:", failure)
            print(f"{count} ModSecurity request cases; {len(failures)} failures")
            return bool(failures)
        finally:
            server.terminate()
            server.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
