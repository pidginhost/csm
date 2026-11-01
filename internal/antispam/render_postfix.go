package antispam

// milterHeaders makes rspamd's milter add X-Spam-Status, which learning
// reads to skip mail CSM tagged, and strip inbound copies so a sender
// cannot forge it. X-Spam stays: the proxy worker's own X-Spam: Yes is what
// the host's sieve rules file into Junk.
const milterHeaders = ManagedHeader + "\nuse = [\"x-spam-status\"];\nremove = { \"X-Spam-Status\" = 0; };\n"

// RenderPostfix returns the files CSM owns only on a Postfix host, keyed by
// path: the milter headers and the scope Lua.
func RenderPostfix(s Settings) (map[string]string, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	// ponytail: the scope Lua holds only CSM's marker until its scope rules
	// are rendered here.
	return map[string]string{
		MilterHeadersPath:   milterHeaders,
		PostfixScopeLuaPath: LuaManagedHeader + "\n",
	}, nil
}
