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

# Read CSM auth token from config
my $token = '';
my $listen = 'localhost:9443';
if (open my $fh, '<', '/opt/csm/csm.yaml') {
    while (<$fh>) {
        if (/^\s*auth_token:\s*["']?([^"'\s]+)/) { $token = $1; }
        if (/^\s*listen:\s*["']?([^"'\s]+)/)     { $listen = $1; }
    }
    close $fh;
}

# Default to dashboard
if (!$path || $path eq '/') {
    $path = '/dashboard';
}

# Sanitize path
if ($path !~ m{^/(?:api/|static/|dashboard|findings|history|quarantine|blocked|firewall|login|ws/)}) {
    $path = '/dashboard';
}

my $url = "https://$listen$path";
my $method = $ENV{REQUEST_METHOD} || 'GET';

# Build curl command — use -L to follow redirects, -b for cookie auth
# Write response headers to temp file, body to stdout
my $hdr_file = "/tmp/csm_cgi_$$.hdr";

my @cmd = (
    'curl', '-sk', '-L', '--max-time', '30',
    '-b', "csm_auth=$token",
    '-D', $hdr_file,
);

if ($method eq 'POST') {
    my $content_type = $ENV{CONTENT_TYPE} || 'application/json';
    my $content_length = $ENV{CONTENT_LENGTH} || 0;
    my $body = '';
    if ($content_length > 0) {
        read(STDIN, $body, $content_length);
    }

    push @cmd, '-X', 'POST';
    push @cmd, '-H', "Content-Type: $content_type";
    push @cmd, '--data-binary', $body;

    # Forward CSRF token
    my $csrf = $ENV{HTTP_X_CSRF_TOKEN} || '';
    push @cmd, '-H', "X-CSRF-Token: $csrf" if $csrf;
}

push @cmd, $url;

# Execute — use open() for proper arg handling (no shell interpolation)
my $body = '';
my $pid = open(my $pipe, '-|', @cmd);
if (!$pid) {
    print "Content-Type: text/html\r\nStatus: 502\r\n\r\n";
    print "<h1>CSM Unavailable</h1><p>Could not connect to CSM daemon.</p>";
    exit;
}
{
    local $/;
    $body = <$pipe>;
}
close $pipe;

# Read content-type from saved response headers
my $ct = 'text/html';
if (open my $hf, '<', $hdr_file) {
    while (<$hf>) {
        if (/^content-type:\s*(.+?)$/i) {
            $ct = $1;
            $ct =~ s/[\r\n]//g;
        }
    }
    close $hf;
}
unlink $hdr_file;

if (!defined $body || $body eq '') {
    print "Content-Type: text/html\r\nStatus: 502\r\n\r\n";
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

# Rewrite URLs in HTML to route through CGI proxy
if ($ct =~ /text\/html/) {
    $body =~ s{(href|action)="(/(?:dashboard|findings|history|quarantine|blocked|firewall|login)[^"]*)"}{$1="addon_csm.cgi?path=$2"}g;
    $body =~ s{(href|src)="/static/([^"]+)"}{$1="addon_csm.cgi?path=/static/$2"}g;
    $body =~ s{action="/login"}{action="addon_csm.cgi?path=/login"}g;
}

# Rewrite relative url() in CSS to absolute paths through proxy
# e.g. url("fonts/tabler-icons.woff2") -> url("addon_csm.cgi?path=/static/css/fonts/tabler-icons.woff2")
if ($ct =~ /text\/css/) {
    $body =~ s{url\("fonts/([^"]+?)(?:\?[^"]*)?"\)}{url("addon_csm.cgi?path=/static/css/fonts/$1")}g;
}

print "Content-Type: $ct\r\n";
print "\r\n";
print $body;
