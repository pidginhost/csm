#!/usr/bin/perl
# CSM Security Monitor — WHM Plugin CGI Proxy
# Deployed to: /usr/local/cpanel/whostmgr/docroot/cgi/addon_csm.cgi
# WHM handles authentication before invoking this script.

use strict;
use warnings;

# Read query string
my $qs = $ENV{QUERY_STRING} || '';
my %params;
for my $pair (split /&/, $qs) {
    my ($k, $v) = split /=/, $pair, 2;
    next unless defined $k;
    $v //= '';
    $v =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/ge;
    $params{$k} = $v;
}

my $path = $params{path} || '';

# Read CSM auth token from config (simple regex — no YAML dependency)
my $token = '';
my $listen = 'localhost:9443';
if (open my $fh, '<', '/opt/csm/csm.yaml') {
    while (<$fh>) {
        if (/^\s*auth_token:\s*["']?([^"'\s]+)/) { $token = $1; }
        if (/^\s*listen:\s*["']?([^"'\s]+)/)     { $listen = $1; }
    }
    close $fh;
}

# If no path — serve the main dashboard page
if (!$path || $path eq '/') {
    $path = '/dashboard';
}

# Sanitize path — only allow /api/, /static/, and page routes
if ($path !~ m{^/(?:api/|static/|dashboard|findings|history|quarantine|blocked|login|ws/)}) {
    $path = '/dashboard';
}

# Build target URL
my $url = "https://$listen$path";

# Use curl for HTTPS (always available on cPanel, handles self-signed certs)
my $method = $ENV{REQUEST_METHOD} || 'GET';
my @cmd = ('curl', '-sk', '--max-time', '30',
           '-H', "Authorization: Bearer $token",
           '-H', "Cookie: csm_auth=$token");

if ($method eq 'POST') {
    # Read POST body from STDIN
    my $content_type = $ENV{CONTENT_TYPE} || 'application/json';
    my $content_length = $ENV{CONTENT_LENGTH} || 0;
    my $body = '';
    if ($content_length > 0) {
        read(STDIN, $body, $content_length);
    }

    push @cmd, '-X', 'POST';
    push @cmd, '-H', "Content-Type: $content_type";
    push @cmd, '-d', $body;
}

# Add CSRF token header for POST requests
if ($method eq 'POST') {
    # Read CSRF token from HTTP header forwarded by WHM
    my $csrf = $ENV{HTTP_X_CSRF_TOKEN} || '';
    push @cmd, '-H', "X-CSRF-Token: $csrf" if $csrf;
}

# Include response headers to detect content type
push @cmd, '-i', $url;

my $response = `@cmd 2>/dev/null`;

if (!$response) {
    print "Content-Type: text/html\r\n";
    print "Status: 502\r\n\r\n";
    print <<'HTML';
<!DOCTYPE html>
<html><head><title>CSM Unavailable</title>
<style>body{font-family:system-ui;display:flex;justify-content:center;align-items:center;
min-height:100vh;margin:0;background:#1a2234;color:#c8d3e0}
.card{background:#243049;border-radius:12px;padding:48px;text-align:center}
h1{color:#d63939}p{color:#8899aa;margin-top:16px}</style>
</head><body><div class="card">
<h1>CSM Unavailable</h1>
<p>The CSM daemon is not responding. Check: <code>systemctl status csm</code></p>
</div></body></html>
HTML
    exit;
}

# Parse response: split headers and body
my ($headers_block, $body) = split /\r?\n\r?\n/, $response, 2;
$body //= '';

# Extract content-type from response headers
my $ct = 'text/html';
if ($headers_block =~ /^Content-Type:\s*(.+?)$/mi) {
    $ct = $1;
    $ct =~ s/\r//g;
}

# For HTML responses, rewrite URLs to route through CGI proxy
if ($ct =~ /text\/html/) {
    # Rewrite href="/dashboard" to href="addon_csm.cgi?path=/dashboard"
    $body =~ s{(href|action)="(/[^"]+)"}{$1="addon_csm.cgi?path=$2"}g;
    # Rewrite src="/static/ to route through proxy
    $body =~ s{src="/static/([^"]+)"}{src="addon_csm.cgi?path=/static/$1"}g;
    # Rewrite link href="/static/
    $body =~ s{href="/static/([^"]+)"}{href="addon_csm.cgi?path=/static/$1"}g;
    # Fix login form action
    $body =~ s{action="/login"}{action="addon_csm.cgi?path=/login"}g;
}

# Output
print "Content-Type: $ct\r\n";
print "\r\n";
print $body;
