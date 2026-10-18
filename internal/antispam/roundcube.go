package antispam

import (
	"context"
	"errors"
	"strings"
	"time"
)

// RoundcubeUnavailable prefixes Result.Roundcube when the include could not
// be installed, verified or removed cleanly.
const RoundcubeUnavailable = "unavailable: "

// RoundcubeJunkFolder is the Maildir folder cPanel delivers spam to and
// learning reads.
const RoundcubeJunkFolder = "INBOX.spam"

// RenderRoundcube returns the include that points Roundcube's Junk button
// at the Spam folder (spec 6.4). Its marker follows the PHP opening tag.
func RenderRoundcube() string {
	return "<?php\n" + ManagedHeader + "\n" +
		"$config['junk_mbox'] = '" + RoundcubeJunkFolder + "';\n" +
		"$config['markasjunk_spam_mbox'] = '" + RoundcubeJunkFolder + "';\n"
}

// RoundcubeState is what a fresh Roundcube request loads: the Junk folder
// settings and whether the markasjunk plugin is on.
type RoundcubeState struct {
	JunkMbox, SpamMbox string
	MarkAsJunk         bool
}

// Applied reports whether the Junk button reaches the Spam folder.
func (r RoundcubeState) Applied() bool {
	return r.MarkAsJunk && r.JunkMbox == RoundcubeJunkFolder && r.SpamMbox == RoundcubeJunkFolder
}

// cPanel's Roundcube and its PHP runtime (spec 6.4, spike S10).
const (
	roundcubeDir = "/usr/local/cpanel/base/3rdparty/roundcube/"
	cpanelPHP    = "/usr/local/cpanel/3rdparty/bin/php"
)

// roundcubeScript loads Roundcube's configuration the way a request does,
// defaults first, and prints only the three settings CSM checks. It never
// dumps the configuration.
const roundcubeScript = `define('RCMAIL_VERSION', '1.6');
define('RCUBE_INSTALL_PATH', '` + roundcubeDir + `');
$config = array();
require RCUBE_INSTALL_PATH . 'config/defaults.inc.php';
require RCUBE_INSTALL_PATH . 'config/config.inc.php';
$line = function ($v) {
    if (!is_string($v)) { return ''; }
    if (strpbrk($v, "\r\n") !== false) { exit(1); }
    return $v;
};
$plugins = isset($config['plugins']) && is_array($config['plugins']) ? $config['plugins'] : array();
echo 'junk_mbox=', $line(isset($config['junk_mbox']) ? $config['junk_mbox'] : ''), "\n";
echo 'spam_mbox=', $line(isset($config['markasjunk_spam_mbox']) ? $config['markasjunk_spam_mbox'] : ''), "\n";
echo 'markasjunk=', in_array('markasjunk', $plugins, true) ? '1' : '0', "\n";
`

// RoundcubeEffective evaluates Roundcube's configuration with cPanel's PHP
// and returns the loaded Junk settings.
func RoundcubeEffective(ctx context.Context, run func(context.Context, time.Duration, string, ...string) CommandResult) (RoundcubeState, error) {
	r := run(ctx, 30*time.Second, "env", "DNS=localhost", cpanelPHP, "-d", "display_errors=0", "-r", roundcubeScript)
	if r.Err != nil {
		return RoundcubeState{}, errors.New("cPanel's PHP could not load the Roundcube configuration")
	}
	return ParseRoundcubeState(r.Stdout)
}

// ParseRoundcubeState reads exactly the three key=value lines the script
// prints, in any order.
func ParseRoundcubeState(out string) (RoundcubeState, error) {
	var st RoundcubeState
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || seen[key] {
			return RoundcubeState{}, errors.New("the Roundcube check printed unexpected output")
		}
		seen[key] = true
		switch key {
		case "junk_mbox":
			st.JunkMbox = value
		case "spam_mbox":
			st.SpamMbox = value
		case "markasjunk":
			if value != "0" && value != "1" {
				return RoundcubeState{}, errors.New("the Roundcube check printed unexpected output")
			}
			st.MarkAsJunk = value == "1"
		default:
			return RoundcubeState{}, errors.New("the Roundcube check printed unexpected output")
		}
	}
	if len(seen) != 3 {
		return RoundcubeState{}, errors.New("the Roundcube check printed unexpected output")
	}
	return st, nil
}
