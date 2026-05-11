package webserver

import _ "embed"

// Bumped on every shipped template change. The installer compares the
// version embedded in the on-disk snippet's header to this constant to
// decide whether `upgrade` needs to rewrite the file. Increment in
// lockstep with template content changes.
const TemplateVersion = 4

//go:embed templates/apache.conf
var apacheTemplate string

//go:embed templates/lsws.conf
var lswsTemplate string

//go:embed templates/nginx.conf
var nginxTemplate string
