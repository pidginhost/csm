// Package stalwartsetup works out what a Stalwart server needs before CSM can
// rely on it, and applies it. Inspect only reads; Apply writes the changes
// Inspect planned and reloads Stalwart's settings once.
package stalwartsetup

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/ipmap"
	"github.com/pidginhost/csm/internal/stalwartapi"
)

// API is the part of the Stalwart admin API setup uses.
type API interface {
	TracingLevels(ctx context.Context) ([]stalwartapi.TracingLevel, error)
	SetTracingLevel(ctx context.Context, id, event, level string) error
	HTTPSettings(ctx context.Context) (stalwartapi.HTTPSettings, error)
	SetHTTPSettings(ctx context.Context, h stalwartapi.HTTPSettings) error
	BanPeriods(ctx context.Context) (stalwartapi.BanPeriods, error)
	SetBanPeriods(ctx context.Context, d time.Duration) error
	Listeners(ctx context.Context) ([]stalwartapi.Listener, error)
	ProxyTrustedNetworks(ctx context.Context) ([]string, error)
	SpamSettings(ctx context.Context) (stalwartapi.SpamSettings, error)
	SpamFilterStageOff(ctx context.Context) (bool, error)
	ReloadSettings(ctx context.Context) ([]string, error)
	RoleByDescription(ctx context.Context, description string) (stalwartapi.Role, bool, error)
	SaveRole(ctx context.Context, r stalwartapi.Role) (string, error)
	Domains(ctx context.Context) ([]stalwartapi.Domain, error)
	AccountsNamed(ctx context.Context, name string) ([]stalwartapi.Account, error)
	AccountRoleIDs(ctx context.Context, id string) ([]string, error)
	AccountCredentialTypes(ctx context.Context, id string) ([]string, error)
	CreateAccount(ctx context.Context, name, domainID, roleID string) (string, error)
	SetAccountRole(ctx context.Context, id, roleID string) error
	APIKeys(ctx context.Context, accountID string) ([]stalwartapi.APIKey, error)
	CreateAPIKey(ctx context.Context, accountID, description string, allowedIPs []string) (id, secret string, err error)
	DeleteAPIKeys(ctx context.Context, accountID string, ids []string) error
	SpamRule(ctx context.Context, name string) (stalwartapi.SpamRule, bool, error)
	CreateSpamRule(ctx context.Context, name string, r stalwartapi.SpamRule) error
	SetSpamRuleCondition(ctx context.Context, id string, arms []stalwartapi.RuleArm, elseExpr string) error
	SpamTag(ctx context.Context, tag string) (stalwartapi.SpamTag, bool, error)
	CreateSpamTag(ctx context.Context, tag string, score float64) error
}

// Inputs is what CSM knows about itself.
type Inputs struct {
	// BlockExpiry is CSM's block length; Stalwart's bans are set to it.
	BlockExpiry time.Duration
	// LockManaged is true when the running daemon manages the firewall.
	LockManaged bool
	// LockedPorts are the ports the running firewall locks to listed users.
	LockedPorts []int
	// WebUsers are the web server's users, for the lock line setup suggests.
	WebUsers []string
	// LockUsers are the users csm.yaml's local_port_locks admit on each
	// port, besides root.
	LockUsers map[int][]string
	// PHPUsers maps each user PHP or CGI runs as on this host to what runs
	// as it. Code a site runs as a user the webmail lock admits can connect
	// and forge the forwarded header.
	PHPUsers map[string]string
	// LocalAPI is true when the API address is on this host, the only place
	// CSM's key works from.
	LocalAPI bool
	// AccountDomain names the domain for CSM's service account when Stalwart
	// has several.
	AccountDomain string
	// KeyAccount is the account the key in CSM's key file logs in as; empty
	// when there is no working key.
	KeyAccount string
	// WriteKey stores a new key in CSM's key file.
	WriteKey func(secret string) error
	// Observe is true in observe mode, where the daemon does not write CSM's
	// address list to Stalwart, so doctor does not test it.
	Observe bool
}

// State is a step's outcome.
type State string

const (
	Done    State = "done"
	Change  State = "change"
	Skipped State = "skipped"
	Unsafe  State = "unsafe"
	Warn    State = "warn"
)

// Step is one setup step.
type Step struct {
	Name   string
	State  State
	Detail string
	apply  func(ctx context.Context, api API) error
	// noReload marks a step that changes no Stalwart setting.
	noReload bool
}

// Plan is the setup steps in order.
type Plan struct {
	Steps []Step
	// AddressListOn is true when Stalwart's rule for CSM's address list
	// exists and is switched on.
	AddressListOn bool
	pendingReload bool
}

const (
	failedLoginEvent = "auth.failed"
	spamVerdictEvent = "spam.classify"
	stalwartUser     = "stalwart"
)

// CSM's role, service account and API key in Stalwart.
const (
	ResponseRole    = "CSM response"
	ResponseAccount = "csm-response"
	ResponseKey     = "CSM"
)

// ResponsePermissions are what CSM's key needs beyond the User role: suspend
// accounts, lift bans, keep CSM's address list in Stalwart, and read every
// setting setup and doctor read.
var ResponsePermissions = []string{
	"authenticate", "sysAccountGet", "sysAccountQuery", "sysAccountUpdate",
	"sysBlockedIpGet", "sysBlockedIpQuery", "sysBlockedIpDestroy",
	"sysActionCreate", "actionReloadBlockedIps", "actionClassifySpam",
	"sysEventTracingLevelGet", "sysEventTracingLevelQuery", "sysHttpGet",
	"sysSecurityGet", "sysNetworkListenerGet", "sysNetworkListenerQuery",
	"sysSystemSettingsGet", "sysSpamSettingsGet", "sysMtaStageDataGet",
	"sysRoleGet", "sysRoleQuery", "sysDomainGet", "sysDomainQuery",
	"sysMemoryLookupKeyGet", "sysMemoryLookupKeyQuery", "sysMemoryLookupKeyCreate", "sysMemoryLookupKeyDestroy",
	"actionReloadLookupStores", "sysSpamRuleGet", "sysSpamRuleQuery", "sysSpamTagGet", "sysSpamTagQuery",
}

// keyAddresses limit CSM's key to this host.
var keyAddresses = []string{"127.0.0.1", "::1"}

// ErrNotReloaded means Stalwart stored the settings Apply wrote but did not
// reload them. A later Inspect reads them as done, so the caller must tell
// the operator to restart Stalwart.
var ErrNotReloaded = errors.New("settings stored but not reloaded")

// ErrSettingsWrite marks a failed write of a Stalwart setting: part of it may
// be stored and not reloaded.
var ErrSettingsWrite = errors.New("stalwart setting not written")

// Inspect reads Stalwart's settings and plans each step. It writes nothing.
func Inspect(ctx context.Context, api API, in Inputs) (Plan, error) {
	levels, err := api.TracingLevels(ctx)
	if err != nil {
		return Plan{}, err
	}
	httpSettings, err := api.HTTPSettings(ctx)
	if err != nil {
		return Plan{}, err
	}
	listeners, err := api.Listeners(ctx)
	if err != nil {
		return Plan{}, err
	}
	bans, err := api.BanPeriods(ctx)
	if err != nil {
		return Plan{}, err
	}
	proxy, err := api.ProxyTrustedNetworks(ctx)
	if err != nil {
		return Plan{}, err
	}
	spamStep, err := inspectSpamFilter(ctx, api)
	if err != nil {
		return Plan{}, err
	}
	listStep, listOn, err := inspectAddressList(ctx, api)
	if err != nil {
		return Plan{}, err
	}
	response, err := inspectResponse(ctx, api, in)
	if err != nil {
		return Plan{}, err
	}
	return Plan{Steps: append([]Step{
		failedLoginStep(levels),
		clientAddressStep(httpSettings, listeners, in),
		banExpiryStep(bans, in.BlockExpiry),
		proxyStep(listeners, proxy),
		tracingStep("spam verdict logging", spamVerdictEvent, levels, "; rejected and discarded spam is not logged until then"),
		spamStep,
		listStep,
	}, response...), AddressListOn: listOn}, nil
}

// inspectResponse plans CSM's role, its service account and the account's
// key. The apply of each later step reads the ids an earlier one creates.
func inspectResponse(ctx context.Context, api API, in Inputs) ([]Step, error) {
	steps := []Step{{Name: "response role"}, {Name: "response account"}, {Name: "response key"}}
	role, account, key := &steps[0], &steps[1], &steps[2]
	skip := func(from []Step, why string) []Step {
		for i := range from {
			from[i].State, from[i].Detail = Skipped, why
		}
		return steps
	}
	if !in.LocalAPI {
		return skip(steps, "Stalwart's API address is not on this host, and CSM's key works only from this host"), nil
	}

	user, found, err := api.RoleByDescription(ctx, "User")
	if err != nil {
		return nil, err
	}
	if !found {
		role.State = Warn
		role.Detail = `Stalwart has no role named "User", which CSM's role must include for its key to change user accounts; restore it in Stalwart's admin interface`
		return skip(steps[1:], "needs CSM's role"), nil
	}
	current, haveRole, err := api.RoleByDescription(ctx, ResponseRole)
	if err != nil {
		return nil, err
	}
	roleID := current.ID
	var missing []string
	for _, p := range ResponsePermissions {
		if !slices.Contains(current.Enabled, p) {
			missing = append(missing, p)
		}
	}
	if !slices.Contains(current.RoleIDs, user.ID) {
		missing = append(missing, "the User role")
	}
	switch {
	case !haveRole:
		role.State, role.Detail = Change, fmt.Sprintf("create role %q with CSM's permissions and the User role", ResponseRole)
	case len(current.Disabled) > 0:
		role.State, role.Detail = Change, fmt.Sprintf("role %q denies permissions; reset it to CSM's permissions and the User role", ResponseRole)
	case len(missing) > 0:
		role.State, role.Detail = Change, fmt.Sprintf("role %q lacks %s; reset it to CSM's permissions and the User role", ResponseRole, strings.Join(missing, ", "))
	default:
		role.State, role.Detail = Done, fmt.Sprintf("role %q holds CSM's permissions and the User role", ResponseRole)
	}
	if role.State == Change {
		want := stalwartapi.Role{ID: current.ID, Description: ResponseRole, Enabled: slices.Clone(ResponsePermissions), RoleIDs: []string{user.ID}}
		role.noReload = true
		role.apply = func(ctx context.Context, api API) (err error) {
			roleID, err = api.SaveRole(ctx, want)
			return err
		}
	}

	accounts, err := api.AccountsNamed(ctx, ResponseAccount)
	if err != nil {
		return nil, err
	}
	accountID, name := "", ""
	switch len(accounts) {
	case 0:
		domain, why, domainErr := responseDomain(ctx, api, in.AccountDomain)
		if domainErr != nil {
			return nil, domainErr
		}
		if why != "" {
			account.State, account.Detail = Skipped, why
			return skip(steps[2:], "needs CSM's service account"), nil
		}
		name = ResponseAccount + "@" + domain.Name
		account.State = Change
		account.Detail = fmt.Sprintf("create account %s with only CSM's role and no password; it can receive mail at that address", name)
		account.noReload = true
		account.apply = func(ctx context.Context, api API) (err error) {
			accountID, err = api.CreateAccount(ctx, ResponseAccount, domain.ID, roleID)
			return err
		}
	case 1:
		a := accounts[0]
		accountID, name = a.ID, cmp.Or(a.Email, a.Name)
		roles, rolesErr := api.AccountRoleIDs(ctx, a.ID)
		if rolesErr != nil {
			return nil, rolesErr
		}
		creds, credsErr := api.AccountCredentialTypes(ctx, a.ID)
		if credsErr != nil {
			return nil, credsErr
		}
		// The key's loopback limit does not cover a password, and a key
		// for an account that cannot sign in never works: setup adopts an
		// existing account only when it holds nothing of anyone else's.
		ours := haveRole && slices.Equal(roles, []string{current.ID})
		why := ""
		switch {
		case a.SignInDisabled:
			why = fmt.Sprintf("sign-ins are stopped for %s; allow them in Stalwart or remove the account, then run setup", name)
		case slices.Contains(creds, "Password") || slices.Contains(creds, "AppPassword"):
			why = fmt.Sprintf("%s has a password, and CSM's account must have none; remove the password or the account, then run setup", name)
		case slices.ContainsFunc(creds, func(k string) bool { return k != "ApiKey" }):
			// A kind CSM does not know, or none, may sign in from anywhere.
			why = fmt.Sprintf("%s has a sign-in credential CSM does not know; remove it or the account, then run setup", name)
		case !ours && len(creds) > 0:
			why = fmt.Sprintf("an account named %s exists that CSM did not make; remove or rename it, then run setup", name)
		}
		if why != "" {
			account.State, account.Detail = Warn, why
			return skip(steps[2:], "needs CSM's own service account"), nil
		}
		if ours {
			account.State, account.Detail = Done, name+" holds only CSM's role and no password"
			break
		}
		account.State, account.Detail = Change, name+" must hold only CSM's role; set it"
		account.noReload = true
		account.apply = func(ctx context.Context, api API) error {
			return api.SetAccountRole(ctx, a.ID, roleID)
		}
	default:
		names := make([]string, len(accounts))
		for i, a := range accounts {
			names[i] = cmp.Or(a.Email, a.Name)
		}
		account.State = Warn
		account.Detail = fmt.Sprintf("%d accounts are named %s (%s); CSM needs exactly one, so delete the others in Stalwart's admin interface",
			len(accounts), ResponseAccount, strings.Join(names, ", "))
		return skip(steps[2:], "needs exactly one service account"), nil
	}

	// Stalwart does not list secrets, so with several keys CSM cannot tell
	// which one its file holds; replacing them all removes the others.
	var keys []stalwartapi.APIKey
	if accountID != "" && in.KeyAccount == accountID {
		if keys, err = api.APIKeys(ctx, accountID); err != nil {
			return nil, err
		}
		if len(keys) == 1 {
			key.State, key.Detail = Done, "CSM's key file holds the only key of "+name
			return steps, nil
		}
	}
	key.State = Change
	switch {
	case in.KeyAccount == "":
		key.Detail = "CSM's key file holds no working key"
	case in.KeyAccount != accountID:
		key.Detail = "the key in CSM's key file belongs to another account"
	case len(keys) == 0:
		key.Detail = "Stalwart lists no key of " + name
	default:
		key.Detail = name + " has extra API keys besides the one in CSM's key file"
	}
	key.Detail += fmt.Sprintf("; create a key of %s that works only from this host, store it in the key file and delete the account's other keys", name)
	key.noReload = true
	writeKey := in.WriteKey
	key.apply = func(ctx context.Context, api API) error {
		return replaceKey(ctx, api, accountID, writeKey)
	}
	return steps, nil
}

// responseDomain picks the domain for CSM's service account. why says what
// is missing when there is no single choice.
func responseDomain(ctx context.Context, api API, want string) (d stalwartapi.Domain, why string, err error) {
	domains, err := api.Domains(ctx)
	if err != nil {
		return d, "", err
	}
	if want != "" {
		// Aliases do not count: the account's address is in the domain itself.
		for _, d := range domains {
			if asciiEqualFold(d.Name, want) {
				return d, "", nil
			}
		}
		return d, fmt.Sprintf("Stalwart has no domain named %s; name one of its domains with --account-domain", want), nil
	}
	switch len(domains) {
	case 0:
		return d, "Stalwart has no domain for CSM's service account; add one first", nil
	case 1:
		return domains[0], "", nil
	}
	return d, fmt.Sprintf("Stalwart has %d domains; choose the one for CSM's service account with --account-domain NAME", len(domains)), nil
}

// asciiEqualFold ignores ASCII case only: a Unicode fold maps other letters,
// such as the Kelvin sign, onto ASCII ones.
func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	lower := func(c byte) byte {
		if 'A' <= c && c <= 'Z' {
			return c + 'a' - 'A'
		}
		return c
	}
	for i := 0; i < len(a); i++ {
		if lower(a[i]) != lower(b[i]) {
			return false
		}
	}
	return true
}

// replaceKey creates a key of the account, stores it, then deletes the
// account's other keys. A key that could not be stored is deleted again, so
// the old key keeps working. The secret goes to write and nowhere else.
func replaceKey(ctx context.Context, api API, accountID string, write func(string) error) (result error) {
	id, secret, err := api.CreateAPIKey(ctx, accountID, ResponseKey, keyAddresses)
	if err != nil {
		return err
	}
	defer func() {
		if result != nil {
			if message := stalwartapi.Redact(result.Error(), "", secret); message != result.Error() {
				result = errors.New(message)
			}
		}
	}()
	if err = write(secret); err != nil {
		if delErr := api.DeleteAPIKeys(ctx, accountID, []string{id}); delErr != nil {
			return errors.Join(err, fmt.Errorf("deleting the key that was not stored: %w", delErr))
		}
		return err
	}
	keys, err := api.APIKeys(ctx, accountID)
	if err == nil {
		var old []string
		for _, k := range keys {
			if k.ID != id {
				old = append(old, k.ID)
			}
		}
		if len(old) > 0 {
			err = api.DeleteAPIKeys(ctx, accountID, old)
		}
	}
	if err != nil {
		return fmt.Errorf("the new key is stored and works, but the account's older keys remain; delete them in Stalwart's admin interface: %w", err)
	}
	return nil
}

func inspectSpamFilter(ctx context.Context, api API) (Step, error) {
	spam, settingsErr := api.SpamSettings(ctx)
	if errors.Is(settingsErr, stalwartapi.ErrUnauthorized) {
		return Step{}, settingsErr
	}
	stageOff, stageErr := api.SpamFilterStageOff(ctx)
	if errors.Is(stageErr, stalwartapi.ErrUnauthorized) {
		return Step{}, stageErr
	}
	// These reads only inform the operator. Their failure must not block
	// unrelated setup changes or put server error text in the plan.
	s := Step{Name: "spam filter", State: Warn, Detail: "Cannot read Stalwart's spam filter status; check it in Stalwart's admin interface"}
	if settingsErr == nil && stageErr == nil {
		s = spamFilterStep(spam, stageOff)
	}
	return s, nil
}

// AddressListRule is the Stalwart spam rule that scores senders on CSM's
// address list.
const AddressListRule = "CSM_IP"

// AddressListArms is the rule's condition: one arm per symbol, strongest
// first, so the first match is the strongest listing of the sender.
func AddressListArms() []stalwartapi.RuleArm {
	var arms []stalwartapi.RuleArm
	for _, s := range ipmap.Symbols() {
		arms = append(arms, stalwartapi.RuleArm{
			If: fmt.Sprintf("key_exists('%s', remote_ip) || (is_ipv6_addr(remote_ip) && key_exists('%s', ip_reverse_name(remote_ip)))",
				ipmap.StalwartNamespace(s, false), ipmap.StalwartNamespace(s, true)),
			Then: "'" + s.Name + "'",
		})
	}
	return arms
}

// inspectAddressList plans the rule that has Stalwart score senders on CSM's
// address list, and its tags. on is true when the rule exists and is switched
// on. A refused login stops setup; any other failed read is a warning, so a
// key from before the address list does not block the other steps.
func inspectAddressList(ctx context.Context, api API) (Step, bool, error) {
	s, on, err := addressListStep(ctx, api)
	if errors.Is(err, stalwartapi.ErrUnauthorized) {
		return Step{}, false, err
	}
	if err != nil {
		s = Step{Name: "address list", State: Warn, Detail: "Cannot read Stalwart's spam rules; run csm stalwart setup with an admin login"}
	}
	return s, on, nil
}

// addressListStep reads the rule and its tags. The rule's own switch is the
// operator's: setup creates the rule on but never switches it back on, and
// never changes a tag's score.
func addressListStep(ctx context.Context, api API) (s Step, on bool, err error) {
	s = Step{Name: "address list", State: Warn}
	rule, found, err := api.SpamRule(ctx, AddressListRule)
	if err != nil {
		return s, false, err
	}
	switch {
	case found && rule.Type != "Any":
		// The type is server text, so the detail does not quote it.
		s.Detail = "Stalwart has a rule named " + AddressListRule + " that CSM did not make; remove or rename it, then run setup"
		return s, false, nil
	case found && !rule.Enabled:
		s.State, s.Detail = Done, "rule "+AddressListRule+" is switched off in Stalwart, so CSM's address list adds no score"
		return s, false, nil
	}
	on = found

	var scores, nonScoring, missing []string
	var create []ipmap.Symbol
	for _, sym := range ipmap.Symbols() {
		tag, have, err := api.SpamTag(ctx, sym.Name)
		if err != nil {
			return s, on, err
		}
		if !have {
			missing = append(missing, sym.Name)
			create = append(create, sym)
			continue
		}
		if tag.Type == "Score" {
			scores = append(scores, sym.Name+" "+strconv.FormatFloat(tag.Score, 'f', -1, 64))
		} else {
			nonScoring = append(nonScoring, sym.Name)
		}
	}
	arms := AddressListArms()
	reset := found && (!slices.Equal(rule.Arms, arms) || rule.Else != "false")
	switch {
	case !found:
		var strongest int
		for _, sym := range ipmap.Symbols() {
			strongest = max(strongest, sym.Tenths())
		}
		s.Detail = fmt.Sprintf("create rule %s: Stalwart adds up to %s to the spam score of senders on CSM's address list, so more of their mail goes to Junk, or is rejected or discarded at the scores set in Stalwart; switch the rule off in Stalwart to stop",
			AddressListRule, strconv.FormatFloat(float64(strongest)/10, 'f', -1, 64))
	case len(missing) > 0 || reset:
		var parts []string
		if len(missing) > 0 {
			noun := "tag"
			if len(missing) > 1 {
				noun = "tags"
			}
			parts = append(parts, "create the missing "+noun+" "+strings.Join(missing, ", "))
		}
		if reset {
			parts = append(parts, "reset the condition of rule "+AddressListRule+" to match CSM's address list")
		}
		s.Detail = strings.Join(parts, "; ")
	default:
		s.State, s.Detail = Done, "rule "+AddressListRule+" adds "+strings.Join(scores, ", ")+" to senders on CSM's address list"
		if len(scores) == 0 {
			s.Detail = "rule " + AddressListRule + " has no scoring tags"
		}
		if len(nonScoring) > 0 {
			s.Detail += "; non-scoring tags: " + strings.Join(nonScoring, ", ")
		}
		return s, on, nil
	}
	s.State = Change
	s.apply = func(ctx context.Context, api API) error {
		// Created tags leave the list, so a retried Apply does not repeat them.
		for len(create) > 0 {
			if err := api.CreateSpamTag(ctx, create[0].Name, float64(create[0].Tenths())/10); err != nil {
				return err
			}
			create = create[1:]
		}
		switch {
		case !found:
			return api.CreateSpamRule(ctx, AddressListRule, stalwartapi.SpamRule{Arms: arms, Else: "false"})
		case reset:
			return api.SetSpamRuleCondition(ctx, rule.ID, arms, "false")
		}
		return nil
	}
	return s, on, nil
}

// Apply makes each planned change in order, then reloads Stalwart's settings
// once. It makes no call when nothing changes. A failed write stops it, and
// the settings written before it are still reloaded: a later run reads them
// as done, so they must not be left stored but inactive.
func (p *Plan) Apply(ctx context.Context, api API) ([]string, error) {
	var failed error
	for i := range p.Steps {
		s := &p.Steps[i]
		if s.State != Change || s.apply == nil {
			continue
		}
		if err := s.apply(ctx, api); err != nil {
			failed = fmt.Errorf("%s: %w", s.Name, err)
			if !s.noReload {
				failed = settingsWriteError{failed}
			}
			break
		}
		if !s.noReload {
			p.pendingReload = true
		}
		s.apply = nil
	}
	if !p.pendingReload {
		return nil, failed
	}
	warnings, err := api.ReloadSettings(ctx)
	if err != nil {
		return nil, errors.Join(failed, fmt.Errorf("%w: %w", ErrNotReloaded, err))
	}
	p.pendingReload = false
	return warnings, failed
}

// settingsWriteError adds ErrSettingsWrite to a failed settings step's error
// without changing its text.
type settingsWriteError struct{ error }

func (e settingsWriteError) Unwrap() []error { return []error{e.error, ErrSettingsWrite} }

func failedLoginStep(levels []stalwartapi.TracingLevel) Step {
	return tracingStep("failed-login logging", failedLoginEvent, levels, "")
}

// tracingStep raises event to info unless its override already logs it; why
// ends the detail of a step that still has to change.
func tracingStep(name, event string, levels []stalwartapi.TracingLevel, why string) Step {
	s := Step{Name: name}
	id, level := "", ""
	for _, l := range levels {
		if l.Event == event {
			id, level = l.ID, l.Level
			break
		}
	}
	switch level {
	case "info", "warn", "error":
		s.State, s.Detail = Done, fmt.Sprintf("%s is logged at %s", event, level)
		return s
	case "":
		s.Detail = fmt.Sprintf("%s has no log level of its own; set it to info%s", event, why)
	default:
		s.Detail = fmt.Sprintf("%s is logged at %s; set it to info%s", event, level, why)
	}
	s.State = Change
	s.apply = func(ctx context.Context, api API) error {
		return api.SetTracingLevel(ctx, id, event, "info")
	}
	return s
}

// spamFilterStep only reports the filter's switch and action scores; the address list is a separate step.
func spamFilterStep(sp stalwartapi.SpamSettings, stageOff bool) Step {
	s := Step{Name: "spam filter"}
	if !sp.Enabled || stageOff {
		s.State = Warn
		s.Detail = "Stalwart's spam filter is off, so inbound mail is not filtered; switch it on in Stalwart's admin interface"
		return s
	}
	// A score of 0 switches that action off.
	act := func(verb string, score float64) string {
		if score > 0 {
			return verb + " at " + strconv.FormatFloat(score, 'f', -1, 64)
		}
		return "never " + verb
	}
	s.State = Done
	s.Detail = "on; " + act("files spam to Junk", sp.ScoreSpam) + ", " + act("rejects", sp.ScoreReject) + ", " + act("discards", sp.ScoreDiscard)
	return s
}

// clientAddressStep decides whether Stalwart's HTTP listeners may take the
// client address from X-Forwarded-For. That is only safe when every HTTP
// listener is reachable from this host alone, CSM's running firewall lets
// only the web server and Stalwart connect to it, and no PHP or CGI runs as a
// user that lock admits: otherwise anyone who can connect can claim any
// address.
func clientAddressStep(h stalwartapi.HTTPSettings, listeners []stalwartapi.Listener, in Inputs) Step {
	s := Step{Name: "webmail client addresses"}
	forwarded := h.ClientIPSource != "" && h.ClientIPSource != "peer"

	var ports []int
	var public []string
	for _, l := range listeners {
		if l.Protocol != "http" {
			continue
		}
		if len(l.Bind) == 0 {
			public = append(public, l.Name+" has no known bind address")
		}
		for _, b := range l.Bind {
			if !b.Addr().Unmap().IsLoopback() {
				public = append(public, fmt.Sprintf("%s binds %s", l.Name, b))
			}
			if p := int(b.Port()); !slices.Contains(ports, p) {
				ports = append(ports, p)
			}
		}
	}
	if len(ports) == 0 && len(public) == 0 {
		s.State, s.Detail = Done, "Stalwart has no HTTP listener"
		return s
	}
	slices.Sort(ports)

	reason := ""
	switch {
	case len(public) > 0:
		reason = fmt.Sprintf("listener %s, reachable from other hosts; bind every HTTP listener to 127.0.0.1 behind the web server first",
			strings.Join(public, ", listener "))
	case !in.LockManaged || !allLocked(ports, in.LockedPorts):
		state := "CSM's running firewall does not lock the webmail port"
		if !in.LockManaged {
			state = "CSM's daemon is not managing the firewall"
		}
		reason = fmt.Sprintf("%s; add %s under firewall in csm.yaml and restart CSM", state, lockLine(ports, in.WebUsers))
	default:
		if shared := sharedPHPUsers(ports, in); len(shared) > 0 {
			reason = fmt.Sprintf("PHP or CGI runs as a user the webmail port lock admits: %s, so code a site runs can connect and forge the header; run PHP-FPM pools and CGI as their own users, or lock the port to a web server user PHP does not use",
				strings.Join(shared, ", "))
		}
	}

	switch {
	case reason != "" && forwarded:
		s.State = Unsafe
		s.Detail = fmt.Sprintf("Stalwart takes client addresses from %s, which anyone who can connect can forge: %s; until then set it back to peer in Stalwart",
			h.ClientIPSource, reason)
	case reason != "":
		s.State, s.Detail = Skipped, reason
	case h == safeForwarded:
		s.State, s.Detail = Done, "client addresses come from X-Forwarded-For (1 hop) behind CSM's port lock"
	default:
		s.State = Change
		s.Detail = "client addresses are the web server's; take them from X-Forwarded-For (1 hop). " + webServerHeader
		if forwarded {
			// More hops, or a header the web server does not set, lets the
			// client choose the address Stalwart reads.
			s.Detail = fmt.Sprintf("client addresses come from %s with %d hops, which a client can forge; take them from X-Forwarded-For (1 hop). %s",
				h.ClientIPSource, h.ForwardedHops, webServerHeader)
		}
		s.apply = func(ctx context.Context, api API) error {
			return api.SetHTTPSettings(ctx, safeForwarded)
		}
	}
	return s
}

// webServerHeader is the condition setup cannot check: with one hop Stalwart
// reads the last X-Forwarded-For entry, which must be the web server's own.
const webServerHeader = "The web server must set the header itself, as nginx does with proxy_set_header X-Forwarded-For $remote_addr or $proxy_add_x_forwarded_for; without it a client chooses the address"

// safeForwarded takes the address the web server, the only hop, appends.
var safeForwarded = stalwartapi.HTTPSettings{ClientIPSource: "xForwardedFor", ForwardedHops: 1}

// sharedPHPUsers lists, with what runs as each, the users the lock on any of
// ports admits, root included, that PHP or CGI also runs as.
func sharedPHPUsers(ports []int, in Inputs) []string {
	var out []string
	for _, p := range ports {
		for _, user := range append([]string{"root"}, in.LockUsers[p]...) {
			if source, ok := in.PHPUsers[user]; ok {
				if entry := user + " (" + source + ")"; !slices.Contains(out, entry) {
					out = append(out, entry)
				}
			}
		}
	}
	slices.Sort(out)
	return out
}

func allLocked(ports, locked []int) bool {
	for _, p := range ports {
		if !slices.Contains(locked, p) {
			return false
		}
	}
	return true
}

// lockLine is the csm.yaml line that locks ports to the web users and
// Stalwart.
func lockLine(ports []int, webUsers []string) string {
	users := slices.Clone(webUsers)
	if !slices.Contains(users, stalwartUser) {
		users = append(users, stalwartUser)
	}
	entries := make([]string, len(ports))
	for i, p := range ports {
		entries[i] = strconv.Quote(strconv.Itoa(p) + ":" + strings.Join(users, ","))
	}
	return "local_port_locks: [" + strings.Join(entries, ", ") + "]"
}

func banExpiryStep(b stalwartapi.BanPeriods, want time.Duration) Step {
	s := Step{Name: "ban expiry"}
	if want <= 0 {
		s.State, s.Detail = Skipped, "CSM has no block length"
		return s
	}
	same := func(d *time.Duration) bool { return d != nil && *d == want }
	if same(b.Auth) && same(b.Abuse) && same(b.Scan) {
		s.State, s.Detail = Done, fmt.Sprintf("failed-login, abuse and scan bans last %s, as CSM's blocks do", fmtPeriod(&want))
		return s
	}
	s.State = Change
	s.Detail = fmt.Sprintf("failed-login bans last %s, abuse %s, scan %s; set them to CSM's block length, %s",
		fmtPeriod(b.Auth), fmtPeriod(b.Abuse), fmtPeriod(b.Scan), fmtPeriod(&want))
	s.apply = func(ctx context.Context, api API) error { return api.SetBanPeriods(ctx, want) }
	return s
}

func fmtPeriod(d *time.Duration) string {
	switch {
	case d == nil:
		return "permanent"
	case *d%time.Hour == 0:
		return strconv.FormatInt(int64(*d/time.Hour), 10) + "h"
	case *d%time.Minute == 0:
		return strconv.FormatInt(int64(*d/time.Minute), 10) + "m"
	}
	return d.String()
}

// proxyStep reports mail listeners that accept the PROXY protocol: their log
// addresses come from the proxy's header, which CSM does not handle yet.
func proxyStep(listeners []stalwartapi.Listener, global []string) Step {
	s := Step{Name: "proxy protocol listeners"}
	var names []string
	for _, l := range listeners {
		if l.Protocol == "http" {
			continue
		}
		if len(l.ProxyNetworks) > 0 || len(global) > 0 {
			names = append(names, l.Name)
		}
	}
	if len(names) == 0 {
		s.State, s.Detail = Done, "no mail listener accepts the PROXY protocol"
		return s
	}
	s.State = Warn
	s.Detail = fmt.Sprintf("%s accept the PROXY protocol; CSM still blocks the addresses they log, so make sure only your proxies are trusted",
		strings.Join(names, ", "))
	return s
}
