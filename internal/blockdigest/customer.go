package blockdigest

import "time"

// CustomerHit is an address that logged in successfully as a customer: the
// kind of login (cpanel, webmail, smtp, imap, ftp), the account or mailbox
// when the log named one, and when it was seen.
type CustomerHit struct {
	IP, Kind, Account string
	At                time.Time
}
