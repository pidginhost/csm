package webserver

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Each occurrence matters: one shared file can be loaded in several sites.
// Apache's dump supplies the parent line and indentation, including only
// includes whose conditions passed. Text alone cannot establish that.
type apacheInclude struct {
	path     string
	line     int
	indent   int
	children []*apacheInclude
}

func parseApacheIncludes(dump string) (*apacheInclude, error) {
	var root *apacheInclude
	var stack []*apacheInclude
	for _, raw := range strings.Split(dump, "\n") {
		line := strings.TrimLeft(raw, " \t")
		if !strings.HasPrefix(line, "(") {
			continue
		}
		label, path, ok := strings.Cut(line, ") ")
		path = strings.TrimSpace(path)
		if !ok || !strings.HasPrefix(path, "/") {
			return nil, fmt.Errorf("invalid Apache include record: %q", line)
		}
		node := &apacheInclude{path: path, indent: len(raw) - len(line)}
		if label == "(*" {
			if root != nil {
				return nil, fmt.Errorf("multiple Apache include roots")
			}
			root = node
		} else {
			n, err := strconv.Atoi(strings.TrimPrefix(label, "("))
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("invalid Apache include line: %q", label)
			}
			node.line = n
			for len(stack) > 0 && stack[len(stack)-1].indent >= node.indent {
				stack = stack[:len(stack)-1]
			}
			if len(stack) == 0 {
				return nil, fmt.Errorf("apache include has no parent: %q", path)
			}
			parent := stack[len(stack)-1]
			if nchildren := len(parent.children); nchildren > 0 && parent.children[nchildren-1].line > n {
				return nil, fmt.Errorf("apache includes are out of order: %q", path)
			}
			parent.children = append(parent.children, node)
		}
		stack = append(stack, node)
	}
	if root == nil {
		return nil, fmt.Errorf("apache did not report its loaded configuration files")
	}
	return root, nil
}

type apacheSiteCoverage struct {
	inSite, included, missing bool
}

func (c *apacheSiteCoverage) visit(file *apacheInclude) error {
	if file.path == plainApacheSiteSnippetPath {
		if c.inSite {
			c.included = true
		}
		return nil
	}
	// #nosec G304 -- a configuration file Apache itself reports loading.
	data, err := os.ReadFile(file.path)
	if err != nil {
		return err
	}
	child := 0
	var logical string
	for i, line := range strings.Split(string(data), "\n") {
		logical += strings.TrimSuffix(line, "\r")
		if strings.HasSuffix(logical, "\\") {
			logical = strings.TrimSuffix(logical, "\\")
			continue
		}
		fields := strings.Fields(logical)
		logical = ""
		if len(fields) > 0 {
			switch strings.ToLower(fields[0]) {
			case "<virtualhost":
				if c.inSite {
					return fmt.Errorf("nested VirtualHost in %s", file.path)
				}
				c.inSite, c.included = true, false
			case "</virtualhost>":
				if !c.inSite {
					return fmt.Errorf("unmatched VirtualHost end in %s", file.path)
				}
				c.missing = c.missing || !c.included
				c.inSite = false
			}
		}
		for child < len(file.children) && file.children[child].line <= i+1 {
			if err := c.visit(file.children[child]); err != nil {
				return err
			}
			child++
		}
	}
	if child != len(file.children) || logical != "" {
		return fmt.Errorf("apache configuration changed while checking %s", file.path)
	}
	return nil
}
