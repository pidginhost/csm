package webserver

import (
	"strings"
	"testing"
)

func FuzzApacheIncludes(f *testing.F) {
	f.Add("Included configuration files:\n  (*) /etc/apache2/apache2.conf\n    (12) /etc/apache2/sites-enabled/example.conf\n")
	f.Add("  (*) /etc/apache2/apache2.conf\n    (2) /etc/apache2/site with spaces.conf\n      (1) /var/cache/csm/apache-challenge-site.conf\n")
	f.Add("Syntax OK\n")
	f.Fuzz(func(t *testing.T, dump string) {
		root, err := parseApacheIncludes(dump)
		if err != nil {
			return
		}
		if root == nil || root.line != 0 {
			t.Fatal("accepted dump without a root")
		}
		queue := []*apacheInclude{root}
		for len(queue) > 0 {
			node := queue[0]
			queue = queue[1:]
			if !strings.HasPrefix(node.path, "/") {
				t.Fatal("accepted a relative configuration path")
			}
			previous := 0
			for _, child := range node.children {
				if child.indent <= node.indent || child.line <= 0 || child.line < previous {
					t.Fatal("accepted an invalid include hierarchy")
				}
				previous = child.line
				queue = append(queue, child)
			}
		}
	})
}
