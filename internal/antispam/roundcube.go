package antispam

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
