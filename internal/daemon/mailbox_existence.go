package daemon

// mailboxExistence is what a rejected login says about its mailbox.
type mailboxExistence uint8

const (
	mailboxExistenceUnknown mailboxExistence = iota
	mailboxExists
	mailboxMissing
)

// combineMailboxExistence merges two answers about the same mailbox. Each
// database in a Dovecot passdb chain answers on its own, and one database
// that knows the mailbox outweighs any number that do not.
func combineMailboxExistence(a, b mailboxExistence) mailboxExistence {
	if a == b {
		return a
	}
	if a == mailboxExists || b == mailboxExists {
		return mailboxExists
	}
	return mailboxExistenceUnknown
}
