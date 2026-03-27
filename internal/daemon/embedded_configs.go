package daemon

import _ "embed"

//go:embed configs/addon_csm.cgi
var embeddedWHMCGI []byte

//go:embed configs/csm.conf
var embeddedWHMConf []byte

//go:embed configs/csm_modsec_custom.conf
var embeddedModSec []byte
