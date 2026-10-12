package antispam

import (
	"errors"
	"strings"
)

// CheckGenerated verifies that a generated exim.conf carries CSM's hooks
// exactly as rendered: the scanner block in the main configuration, the RCPT
// hook in the RCPT ACL, and the scan hook before the post hook in the DATA
// ACL (spec sections 6.2 item 5 and 6.3 step 3). rcptACL and dataACL come
// from `exim -bP acl_smtp_rcpt acl_smtp_data`. Errors name blocks, never
// configuration text.
func CheckGenerated(conf string, h EximHooks, rcptACL, dataACL string) error {
	if rcptACL == "" || dataACL == "" || rcptACL == dataACL {
		return errors.New("the RCPT and DATA ACL names must be two different names")
	}
	blocks, err := LocateBlocks(conf)
	if err != nil {
		return err
	}
	if err := CheckPlacement(blocks, rcptACL, dataACL); err != nil {
		return err
	}
	lines := strings.Split(conf, "\n")
	text := func(b Placement) string { return strings.Join(lines[b.Begin-1:b.End], "\n") + "\n" }
	var data []string
	for _, b := range blocks {
		switch b.ACL {
		case "":
			if text(b) != h.Config {
				return errors.New("the scanner block differs from the rendered spamd_address")
			}
		case rcptACL:
			if text(b) != h.RCPT {
				return errors.New("the RCPT ACL hook differs from the rendered hook")
			}
		default:
			data = append(data, text(b))
		}
	}
	if data[0] != h.Scan || data[1] != h.Post {
		return errors.New("the DATA ACL hooks differ from the rendered scan and post hooks, or are out of order")
	}
	return nil
}
