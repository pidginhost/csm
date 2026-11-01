package antispam

// MailStack is the mail system antispam integrates with on a host.
type MailStack string

const (
	// StackNone is a host antispam does not support.
	StackNone MailStack = ""
	// StackExim is a cPanel host running Exim.
	StackExim MailStack = "exim"
	// StackPostfix is a host without cPanel running Postfix.
	StackPostfix MailStack = "postfix"
)
