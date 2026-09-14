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


def role_simulation_cases():
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


SESSION = "wordpress_logged_in_0123456789abcdef=admin%7C1789000000%7Ctoken%7Chmac"


def user_enumeration_cases():
    for uri in ("/wp-json/wp/v2/users", "/wp-json/wp/v2/users/", "//wp-json/wp/v2/users/", "/wp-json/wp/v2/users/1", "/wp-json/wp/v2/users?per_page=100", "/WP-JSON/WP/V2/USERS", "/blog/wp-json/wp/v2/users", "/wp-json/wp/v2/%75sers"):
        yield "anonymous " + uri, "GET", uri, "", {}, True
    for uri in ("/?rest_route=/wp/v2/users", "/?rest_route=wp/v2/users", "/?rest_route=%2Fwp%2Fv2%2Fusers", "/?rest_route=/wp/v2/users/1", "/?rest_route=/WP/V2/Users"):
        yield "anonymous query " + uri, "GET", uri, "", {}, True
    for name in ("rest.route", "rest%20route", "+rest_route", "rest[route", "rest_route%00", "rest.route%00ignored"):
        yield "rest_route alias " + name, "GET", "/?" + name + "=/wp/v2/users", "", {}, True
    for uri in ("/wp-json/wp/v2/users%5C", "/?rest_route=/wp/v2/users%5C", "/?rest_route=/wp/v2/users%5C%5C/"):
        yield "trailing backslash " + uri, "GET", uri, "", {}, True
    yield "anonymous write", "POST", "/wp-json/wp/v2/users/me/application-passwords", "", {}, True
    # Only the logged-in cookie exempts: WordPress sets the others for visitors
    # and a cookie value is not a cookie name.
    for cookie in ("wp-settings-1=libraryContent%3Dbrowse", "wordpress_test_cookie=WP%20Cookie%20check", "a=wordpress_logged_in_0123456789abcdef", "wordpress_sec_0123456789abcdef=x"):
        yield "visitor cookie " + cookie, "GET", "/wp-json/wp/v2/users", cookie, {}, True
    nonce = {"X-WP-Nonce": "0123456789"}
    yield "admin application password", "POST", "/wp-json/wp/v2/users/me/application-passwords?_locale=user", SESSION, nonce, False
    yield "admin profile", "GET", "/wp-json/wp/v2/users/me?context=edit&_locale=user", "wp-settings-1=x; " + SESSION + "; wp-settings-time-1=1", nonce, False
    yield "editor author list", "GET", "/wp-json/wp/v2/users?who=authors&per_page=100", SESSION, nonce, False
    yield "admin query route", "GET", "/?rest_route=/wp/v2/users/me", SESSION, nonce, False
    yield "application password client", "GET", "/wp-json/wp/v2/users/me", "", {"Authorization": "Basic YWRtaW46eHh4eA=="}, False
    yield "session without nonce", "GET", "/wp-json/wp/v2/users", SESSION, {}, False
    yield "empty session presence", "GET", "/wp-json/wp/v2/users", "wordpress_logged_in_fixture=", {}, False
    # Exercise ModSecurity's parsing of separate Cookie fields, including a
    # session after other fields. This probes the collection, not HTTP/2 framing
    # or PHP's separate handling of repeated HTTP/1.1 headers.
    for cookies in (("wp-settings-1=x", SESSION), (SESSION, "wp-settings-1=x"), ("a=b", "c=d", SESSION)):
        yield "split session " + repr(cookies), "GET", "/wp-json/wp/v2/users", cookies, {}, False
    yield "split visitor cookies", "GET", "/wp-json/wp/v2/users", ("a=b", "c=d"), {}, True
    yield "anonymous after session", "GET", "/wp-json/wp/v2/users", "", {}, True
    for uri in ("/", "/shop/", "/wp-json/wp/v2/posts", "/wp-json/wp/v2/users-guide", "/wp-json/wp/v2/usersx", "/?rest_route=/wp/v2/users-guide", "/?rest_route=/wp/v2/posts", "/?next=/wp-json/wp/v2/users", "/?redirect_to=/wp/v2/users", "/wp-login.php?redirect_to=%2Fwp-json%2Fwp%2Fv2%2Fusers", "/wp/v2/users", "/docs/wp/v2/users", "/?rest_route=/custom/wp/v2/users", "/?rest_route=/wp-json/wp/v2/users", "/?rest_route=/custom/../wp/v2/users", "/?rest_route=%252Fwp%252Fv2%252Fusers", "/?rest_route=/wp/v2/users%252Fguide", "/?rest_route=/wp/v2/users%5Cguide"):
        yield "unrelated " + uri, "GET", uri, "", {}, False


def user_enumeration_disabled_cases():
    # Removing the public deny ID must still disable both route forms, even
    # when its non-disruptive helper rules remain installed.
    for name, method, uri, cookie, headers, _ in user_enumeration_cases():
        yield name, method, uri, cookie, headers, False


def combined_cases():
    # A session exemption must not disable the independent virtual patches.
    for cookie in (SESSION, "wordpress_logged_in_fixture="):
        for uri in ("/wp-json/wp/v2/users", "/?rest_route=/wp/v2/users"):
            yield "session with weak simulation", "GET", uri, cookie + "; " + WEAK, {}, True
    yield "visitor with strong simulation", "GET", "/wp-json/wp/v2/users", STRONG, {}, True
    yield "session with strong simulation", "GET", "/wp-json/wp/v2/users", SESSION + "; " + STRONG, {}, False


ENUM_HELPERS = ("900130", "900131", "900132")
GROUPS = (
    ("role simulation", ("900128", "900129"), role_simulation_cases),
    ("user enumeration", ("900112", *ENUM_HELPERS), user_enumeration_cases),
    ("user enumeration disabled", ENUM_HELPERS, user_enumeration_disabled_cases),
    ("combined protections", ("900112", "900128", "900129", *ENUM_HELPERS), combined_cases),
)


def request(port, method, uri, cookie, headers):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.putrequest(method, uri)
        for value in cookie if isinstance(cookie, tuple) else (cookie,):
            if value:
                conn.putheader("Cookie", value)
        for key, value in headers.items():
            conn.putheader(key, value)
        conn.endheaders()
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def run_group(conf, enabled, cases):
    # Parse the complete file before excluding unrelated denies, so a bad
    # directive anywhere still fails the configuration-load gate.
    other_ids = [i for i in re.findall(r"\bid:(\d+)", conf.read_text()) if i not in enabled]
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
    'rest_route' => $_GET['rest_route'] ?? null,
    // rest_api_loaded() trims both slash forms before REST dispatch.
    'trimmed_route' => rtrim($_GET['rest_route'] ?? '', "/\\\\"),
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
                # WordPress reads rest_route through PHP, which folds these
                # spellings into the canonical name. Probe a harmless route
                # with the same parameter name to prove each alias is real.
                if name.startswith("rest_route alias "):
                    probe_status, probe = request(port, "GET", uri.replace("users", "posts"), "", {})
                    if probe_status != 200 or json.loads(probe)["rest_route"] != "/wp/v2/posts":
                        failures.append(f"{name}: PHP does not read the parameter as rest_route")
                if name.startswith("trailing backslash ") and "rest_route=" in uri:
                    probe_status, probe = request(port, "GET", uri.replace("users", "posts"), "", {})
                    if probe_status != 200 or json.loads(probe)["trimmed_route"] != "/wp/v2/posts":
                        failures.append(f"{name}: WordPress does not trim the route to the collection")
            if failures:
                print((base / "error.log").read_text()[-5000:])
            return count, failures
        finally:
            server.terminate()
            server.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--conf", type=Path, default=ROOT / "configs/csm_modsec_custom.conf")
    args = parser.parse_args()
    conf = args.conf.resolve()
    failed = False
    for label, enabled, cases in GROUPS:
        count, failures = run_group(conf, enabled, cases)
        for failure in failures:
            print(f"FAIL [{label}]:", failure)
        print(f"{label}: {count} ModSecurity request cases; {len(failures)} failures")
        failed = failed or bool(failures)
    return failed


if __name__ == "__main__":
    raise SystemExit(main())
