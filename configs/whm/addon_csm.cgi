#!/usr/bin/perl
# CSM Security Monitor — WHM Plugin Redirect
# Deployed to: /usr/local/cpanel/whostmgr/docroot/cgi/addon_csm.cgi
# WHM handles authentication before invoking this script.
# Redirects to the standalone CSM WebUI (HTTPS on port 9443).

use strict;
use warnings;

# Read hostname and listen port from config
my $hostname = '';
my $port = '9443';
if (open my $fh, '<', '/opt/csm/csm.yaml') {
    while (<$fh>) {
        if (/^\s*hostname:\s*["']?([^"'\s]+)/) { $hostname = $1; }
        if (/^\s*listen:\s*["']?(?:[^:]+):(\d+)/)  { $port = $1; }
    }
    close $fh;
}

if (!$hostname) {
    print "Content-Type: text/html\r\nStatus: 500\r\n\r\n";
    print "<h1>CSM Configuration Error</h1>";
    print "<p>No hostname configured in /opt/csm/csm.yaml</p>";
    exit;
}

my $url = "https://${hostname}:${port}/dashboard";

print "Status: 302 Found\r\n";
print "Location: $url\r\n";
print "Content-Type: text/html\r\n";
print "\r\n";
print qq{<html><body><p>Redirecting to <a href="$url">CSM Security Monitor</a>...</p></body></html>};
