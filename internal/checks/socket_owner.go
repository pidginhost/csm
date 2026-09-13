package checks

import (
	"fmt"

	"github.com/pidginhost/csm/internal/alert"
)

// AttributeSocketOwner attaches the hosting account identified by a kernel
// socket or connection-event UID. A missing process snapshot does not remove
// this evidence. Root, service and unresolved UIDs remain unattributed.
// The message carries the account too, so dispatch and audit identities keep
// different accounts contacting the same destination separate.
func AttributeSocketOwner(f *alert.Finding, uid uint32) {
	if uid == 0 {
		return
	}
	if owner := HostingAccountForUser(LookupUser(uid)); owner != "" {
		f.TenantID = owner
		f.Message += fmt.Sprintf(" (account %s)", owner)
	}
}
