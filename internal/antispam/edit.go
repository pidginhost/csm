package antispam

import (
	"errors"
	"slices"
	"strings"
)

// fileBlocks finds the CSM blocks of one shared Exim file. Hook files parse
// as the ACL fragment cPanel inlines; exim.conf.local as main configuration.
func fileBlocks(kind TargetKind, content string) ([]Placement, error) {
	if kind == TargetEximHook {
		return locateBlocks(content, "acl", "csm_hook", false)
	}
	blocks, err := LocateBlocks(content)
	if err != nil {
		return nil, err
	}
	// cPanel section markers are not Exim section headers. A block that
	// spans one cannot be removed without taking operator configuration.
	lines := strings.Split(content, "\n")
	for _, b := range blocks {
		for _, line := range lines[b.Begin : b.End-1] {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "@") && strings.HasSuffix(line, "@") {
				return nil, errors.New("a cPanel section starts inside a CSM block")
			}
		}
	}
	return blocks, nil
}

// BlockText returns the one CSM block in content, markers included, exactly
// as it appears there.
func BlockText(kind TargetKind, content string) (string, bool) {
	blocks, err := fileBlocks(kind, content)
	if err != nil || len(blocks) != 1 {
		return "", false
	}
	lines := strings.SplitAfter(content, "\n")
	return strings.Join(lines[blocks[0].Begin-1:blocks[0].End], ""), true
}

// SetBlock returns content with its CSM block replaced by block, or removed
// when block is empty. A hook file gets the block first, so no earlier
// statement in it can skip CSM's hook; exim.conf.local gets it right after
// its @CONFIG@ line. Content outside the block is kept byte for byte.
func SetBlock(kind TargetKind, content, block string) (string, error) {
	blocks, err := fileBlocks(kind, content)
	if err != nil {
		return "", err
	}
	if len(blocks) > 1 {
		return "", errors.New("the file has more than one CSM block")
	}
	lines := strings.SplitAfter(content, "\n")
	if len(blocks) == 1 {
		lines = slices.Delete(lines, blocks[0].Begin-1, blocks[0].End)
	}
	if block != "" {
		at := 0
		if kind == TargetEximLocal {
			at = slices.IndexFunc(lines, func(l string) bool { return strings.TrimSuffix(l, "\n") == "@CONFIG@" })
			if at < 0 {
				return "", errors.New("exim.conf.local has no @CONFIG@ line")
			}
			lines[at] = "@CONFIG@\n"
			at++
		}
		lines = slices.Insert(lines, at, block)
	}
	out := strings.Join(lines, "")
	want := 0
	if block != "" {
		want = 1
	}
	// Content after the block must not continue CSM's last statement.
	if got, err := fileBlocks(kind, out); err != nil || len(got) != want {
		return "", errors.New("the edited file would not hold the CSM block on its own")
	}
	return out, nil
}
