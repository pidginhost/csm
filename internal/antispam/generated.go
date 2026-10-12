package antispam

import (
	"errors"
	"fmt"
	"strings"
)

// CheckGenerated verifies that a generated exim.conf carries CSM's hooks
// exactly as rendered: the scanner block in the main configuration, the RCPT
// hook in the RCPT ACL, and the scan hook before the post hook in the DATA
// ACL (spec sections 6.2 item 5 and 6.3 step 3). rcptACL and dataACL come
// from `exim -bP acl_smtp_rcpt acl_smtp_data`. Errors name blocks, never
// configuration text. Conditional blocks or boundaries cannot prove that the
// hooks are active; macro substitution must leave their statements unchanged.
func CheckGenerated(conf string, h EximHooks, rcptACL, dataACL string) error {
	if rcptACL == "" || dataACL == "" || rcptACL == dataACL {
		return errors.New("the RCPT and DATA ACL names must be two different names")
	}
	blocks, err := locateBlocks(conf, "", "", true)
	if err != nil {
		return err
	}
	// Counts name what is missing without repeating ACL names from the file.
	var nMain, nRCPT, nData, nOther int
	for _, b := range blocks {
		switch b.ACL {
		case "":
			nMain++
		case rcptACL:
			nRCPT++
		case dataACL:
			nData++
		default:
			nOther++
		}
	}
	if nMain != 1 || nRCPT != 1 || nData != 2 || nOther != 0 {
		return fmt.Errorf("found %d scanner, %d RCPT, %d DATA and %d misplaced CSM blocks; want 1, 1, 2 and 0", nMain, nRCPT, nData, nOther)
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
