package checks

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/platform"
)

func withInventoryPanel(t *testing.T, panel platform.Panel) {
	t.Helper()
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	if !platform.SetOverrides(platform.Overrides{Panel: &panel}) {
		t.Fatal("panel fixture refused")
	}
}

func withAccountRoots(t *testing.T, roots ...string) {
	t.Helper()
	prev := accountHomeRoots
	accountHomeRoots = func() []string { return roots }
	t.Cleanup(func() { accountHomeRoots = prev })
}

func inventoryFS(registry, homes []os.DirEntry, registryErr, homesErr error, userdomains string, domainsErr error) *mockOS {
	return &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			switch name {
			case "/var/cpanel/users":
				return registry, registryErr
			case "/home":
				return homes, homesErr
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/userdomains" {
				if domainsErr != nil {
					return nil, domainsErr
				}
				return []byte(userdomains), nil
			}
			return nil, os.ErrNotExist
		},
	}
}

func TestHostingInventoryReadsCPanelState(t *testing.T) {
	withInventoryPanel(t, platform.PanelCPanel)
	withAccountRoots(t, "/home")
	withMockOS(t, inventoryFS(
		[]os.DirEntry{dirEntry("bob", false), dirEntry("alice", false), dirEntry("bad name", false), dirEntry("subdir", true)},
		nil, nil, nil,
		"alice.example: alice\nShop.Bob.Example: bob\nghost.example: ghost\n*: nobody\nbroken line\n",
		nil,
	))
	snap, err := HostingInventory()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"alice", "bob"}; !reflect.DeepEqual(snap.Accounts, want) {
		t.Errorf("accounts = %v, want %v", snap.Accounts, want)
	}
	if want := map[string]string{"alice.example": "alice", "shop.bob.example": "bob"}; !reflect.DeepEqual(snap.Domains, want) || snap.AmbiguousDomains != 0 {
		t.Errorf("domains = %v (ambiguous %d), want %v", snap.Domains, snap.AmbiguousDomains, want)
	}
	g := admission.NewGenerations()
	gens, err := g.Observe(snap.Accounts)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := admission.NewInventory(gens, snap.Domains)
	if err != nil {
		t.Fatalf("the reader's output does not build an inventory: %v", err)
	}
	if got := inv.Resolve(admission.Claim{Kind: admission.ClaimDomain, Value: "shop.bob.example"}).Key(); got != "acct:bob#2" {
		t.Errorf("resolve = %q", got)
	}
}

// cPanel places accounts on any partition its home-match setting allows,
// while the platform reports one account root. The registry, not the homes
// under that root, is the account list.
func TestHostingInventoryCPanelIgnoresHomePartitions(t *testing.T) {
	withInventoryPanel(t, platform.PanelCPanel)
	withAccountRoots(t, "/home")
	registry := []os.DirEntry{dirEntry("alice", false), dirEntry("bob", false)}
	for name, fs := range map[string]*mockOS{
		"account on another partition": inventoryFS(registry, []os.DirEntry{dirEntry("alice", true)}, nil, nil, "", nil),
		"account root unreadable":      inventoryFS(registry, nil, nil, errors.New("permission denied"), "", nil),
	} {
		withMockOS(t, fs)
		snap, err := HostingInventory()
		if err != nil || !reflect.DeepEqual(snap.Accounts, []string{"alice", "bob"}) {
			t.Errorf("%s: HostingInventory = %v %v", name, snap.Accounts, err)
		}
	}
}

func TestHostingInventoryWithoutCPanelUsesAccountHomes(t *testing.T) {
	withInventoryPanel(t, platform.PanelNone)
	withAccountRoots(t, "/home")
	withMockOS(t, inventoryFS(nil, []os.DirEntry{dirEntry("carol", true), dirEntry("lost+found", true), dirEntry("regular", false)}, os.ErrNotExist, nil, "", os.ErrNotExist))
	snap, err := HostingInventory()
	if err != nil || !reflect.DeepEqual(snap.Accounts, []string{"carol"}) || len(snap.Domains) != 0 {
		t.Errorf("HostingInventory = %+v %v", snap, err)
	}
}

// A read failure must fail the whole inventory. Returning the accounts it
// could read would retire the rest and hand them new generations.
func TestHostingInventoryRefusesPartialReads(t *testing.T) {
	denied := errors.New("permission denied")
	alice := []os.DirEntry{dirEntry("alice", false)}
	aliceHome := []os.DirEntry{dirEntry("alice", true)}
	failed := func(name string) {
		t.Helper()
		if snap, err := HostingInventory(); err == nil || snap.Accounts != nil || snap.Domains != nil {
			t.Errorf("%s: expected error and no partial result, got %+v %v", name, snap, err)
		}
	}
	withInventoryPanel(t, platform.PanelCPanel)
	withAccountRoots(t, "/home")
	for name, fs := range map[string]*mockOS{
		"registry missing":       inventoryFS(nil, aliceHome, os.ErrNotExist, nil, "", nil),
		"registry unreadable":    inventoryFS(nil, aliceHome, denied, nil, "", nil),
		"userdomains missing":    inventoryFS(alice, aliceHome, nil, nil, "", os.ErrNotExist),
		"userdomains unreadable": inventoryFS(alice, aliceHome, nil, nil, "", denied),
	} {
		withMockOS(t, fs)
		failed(name)
	}

	withInventoryPanel(t, platform.PanelNone)
	withMockOS(t, inventoryFS(nil, nil, nil, denied, "", nil))
	failed("account root unreadable")

	// One readable root must not hide an unreadable one.
	withAccountRoots(t, "/home", "/home2")
	twoRoots := inventoryFS(nil, aliceHome, nil, nil, "", nil)
	readHome := twoRoots.readDir
	twoRoots.readDir = func(name string) ([]os.DirEntry, error) {
		if name == "/home2" {
			return nil, denied
		}
		return readHome(name)
	}
	withMockOS(t, twoRoots)
	failed("second root unreadable")
}

func TestHostingInventoryMissingRootFailsClosed(t *testing.T) {
	withInventoryPanel(t, platform.PanelNone)
	withAccountRoots(t, "/home", "/home2")
	withMockOS(t, inventoryFS(nil, []os.DirEntry{dirEntry("alice", true)}, os.ErrNotExist, nil, "", os.ErrNotExist))
	if snap, err := HostingInventory(); err == nil || snap.Accounts != nil || snap.Domains != nil {
		t.Fatalf("missing root returned a partial inventory: %+v %v", snap, err)
	}
}

func TestHostingInventoryIgnoresOtherPanelFiles(t *testing.T) {
	withInventoryPanel(t, platform.PanelNone)
	withAccountRoots(t, "/home")
	withMockOS(t, inventoryFS([]os.DirEntry{dirEntry("bob", false)}, []os.DirEntry{dirEntry("alice", true)}, nil, nil, "alice.example: alice", nil))
	snap, err := HostingInventory()
	if err != nil || !reflect.DeepEqual(snap.Accounts, []string{"alice"}) || len(snap.Domains) != 0 {
		t.Fatalf("foreign panel state affected inventory: %+v %v", snap, err)
	}
}

// A domain listed for two owners resolves to neither: its evidence stays
// host-scoped and it is counted. The rest of the inventory stays usable, so
// one bad row cannot take every account scope down.
func TestHostingInventoryExcludesAmbiguousDomains(t *testing.T) {
	for name, rows := range map[string]string{
		"trailing dot":         "shop.example: alice\nshop.example.: bob\n",
		"duplicate":            "shop.example: alice\nshop.example: bob\n",
		"unowned first":        "shop.example: nobody\nshop.example: alice\n",
		"unowned last":         "shop.example: alice\nshop.example: nobody\n",
		"repeated conflict":    "shop.example: alice\nshop.example: bob\nshop.example: alice\n",
		"case alias":           "Shop.Example: alice\nshop.example: bob\n",
		"unlisted owner first": "shop.example: ghost\nshop.example: alice\n",
		"unlisted owner last":  "shop.example: alice\nshop.example: ghost\n",
	} {
		t.Run(name, func(t *testing.T) {
			withInventoryPanel(t, platform.PanelCPanel)
			withAccountRoots(t, "/home")
			withMockOS(t, inventoryFS([]os.DirEntry{dirEntry("alice", false), dirEntry("bob", false)}, nil, nil, nil, "bob.example: bob\n"+rows, nil))
			snap, err := HostingInventory()
			if err != nil || !reflect.DeepEqual(snap.Accounts, []string{"alice", "bob"}) {
				t.Fatalf("one ambiguous domain failed the inventory: %+v %v", snap, err)
			}
			if want := map[string]string{"bob.example": "bob"}; !reflect.DeepEqual(snap.Domains, want) || snap.AmbiguousDomains != 1 {
				t.Fatalf("domains = %v ambiguous %d, want %v and 1", snap.Domains, snap.AmbiguousDomains, want)
			}
			g := admission.NewGenerations()
			gens, err := g.Observe(snap.Accounts)
			if err != nil {
				t.Fatal(err)
			}
			inv, err := admission.NewInventory(gens, snap.Domains)
			if err != nil {
				t.Fatal(err)
			}
			if got := inv.Resolve(admission.Claim{Kind: admission.ClaimDomain, Value: "Shop.Example."}); got != admission.HostOwner() {
				t.Errorf("ambiguous domain resolved to %q", got.Key())
			}
			if got := inv.Resolve(admission.Claim{Kind: admission.ClaimDomain, Value: "bob.example"}).Key(); got != "acct:bob#2" {
				t.Errorf("unambiguous domain resolved to %q", got)
			}
		})
	}
}

func TestHostingInventoryAcceptsRepeatedDomainOwner(t *testing.T) {
	withInventoryPanel(t, platform.PanelCPanel)
	withAccountRoots(t, "/home")
	withMockOS(t, inventoryFS([]os.DirEntry{dirEntry("alice", false)}, nil, nil, nil, "Shop.Example: alice\nshop.example: alice\nshop.example.: alice\n", nil))
	snap, err := HostingInventory()
	if err != nil || !reflect.DeepEqual(snap.Accounts, []string{"alice"}) || !reflect.DeepEqual(snap.Domains, map[string]string{"shop.example": "alice"}) || snap.AmbiguousDomains != 0 {
		t.Fatalf("consistent repeated domain rejected: %+v %v", snap, err)
	}
}

func TestUserDomainParserPreservesLegacyLastOwner(t *testing.T) {
	withMockOS(t, inventoryFS(nil, nil, nil, nil, "# ignored\nshop.example: alice\nShop.Example: bob\nshop.example.: alice\nshop.example: nobody\nunowned.example: nobody\n*: nobody\nbroken line\n", nil))
	want := map[string]string{"shop.example": "bob", "shop.example.": "alice"}
	if got := loadDomainOwners(); !reflect.DeepEqual(got, want) {
		t.Fatalf("legacy domain parsing changed: %v, want %v", got, want)
	}
}

func TestHostingInventoryEmptyReadableHost(t *testing.T) {
	for _, panel := range []platform.Panel{platform.PanelCPanel, platform.PanelNone} {
		t.Run(string(panel), func(t *testing.T) {
			withInventoryPanel(t, panel)
			withAccountRoots(t, "/home")
			withMockOS(t, inventoryFS(nil, nil, nil, nil, "", nil))
			snap, err := HostingInventory()
			want := HostingSnapshot{Accounts: []string{}, Domains: map[string]string{}}
			if err != nil || !reflect.DeepEqual(snap, want) {
				t.Fatalf("empty complete inventory: %+v %v, want %+v", snap, err, want)
			}
		})
	}
}

// Successful reads must be consumable without changing their domain keys.
func TestHostingInventoryCanonicalDomainHandoff(t *testing.T) {
	withInventoryPanel(t, platform.PanelCPanel)
	withMockOS(t, inventoryFS([]os.DirEntry{dirEntry("alice", false)}, nil, nil, nil,
		"Shop.Example.: alice\nmalformed.example..: alice\n..: alice\n", nil))
	snap, err := HostingInventory()
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]string{"shop.example": "alice"}; !reflect.DeepEqual(snap.Domains, want) || snap.AmbiguousDomains != 0 {
		t.Errorf("domains = %v ambiguous %d, want %v and 0", snap.Domains, snap.AmbiguousDomains, want)
	}
	g := admission.NewGenerations()
	gens, err := g.Observe(snap.Accounts)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := admission.NewInventory(gens, snap.Domains)
	if err != nil {
		t.Fatalf("successful snapshot cannot build inventory: %v", err)
	}
	if got := inv.Resolve(admission.Claim{Kind: admission.ClaimDomain, Value: "Shop.Example."}).Key(); got != "acct:alice#1" {
		t.Errorf("resolve = %q", got)
	}
}

// ReadDir and ReadFile may return both useful data and an error. None of
// that data is a complete observation, even if a previous refresh succeeded.
func TestHostingInventoryRejectsDataWithReadError(t *testing.T) {
	denied := errors.New("incomplete read")
	for _, panel := range []platform.Panel{platform.PanelCPanel, platform.PanelNone} {
		paths := []string{"/var/cpanel/users", "/etc/userdomains"}
		if panel == platform.PanelNone {
			paths = []string{"/home", "/home2"}
		}
		for _, failedPath := range paths {
			t.Run(string(panel)+"_"+strings.ReplaceAll(failedPath, "/", "_"), func(t *testing.T) {
				withInventoryPanel(t, panel)
				withAccountRoots(t, "/home", "/home2")
				failRead := false
				withMockOS(t, &mockOS{
					readDir: func(name string) ([]os.DirEntry, error) {
						var entries []os.DirEntry
						switch name {
						case "/var/cpanel/users":
							entries = []os.DirEntry{dirEntry("alice", false), dirEntry("bob", false)}
						case "/home":
							entries = []os.DirEntry{dirEntry("alice", true)}
						case "/home2":
							entries = []os.DirEntry{dirEntry("bob", true)}
						default:
							return nil, os.ErrNotExist
						}
						if failRead && name == failedPath {
							return entries, denied
						}
						return entries, nil
					},
					readFile: func(name string) ([]byte, error) {
						if name != "/etc/userdomains" {
							return nil, os.ErrNotExist
						}
						data := []byte("alice.example: alice\nshop.example: alice\nshop.example: bob\n")
						if failRead && name == failedPath {
							return data, denied
						}
						return data, nil
					},
				})
				before, err := HostingInventory()
				if err != nil || !reflect.DeepEqual(before.Accounts, []string{"alice", "bob"}) {
					t.Fatalf("complete read = %+v %v", before, err)
				}
				failRead = true
				snap, err := HostingInventory()
				if !errors.Is(err, denied) || !reflect.DeepEqual(snap, HostingSnapshot{}) {
					t.Fatalf("incomplete read = %+v %v, want zero snapshot and read error", snap, err)
				}
				failRead = false
				after, err := HostingInventory()
				if err != nil || !reflect.DeepEqual(after, before) {
					t.Fatalf("recovered read = %+v %v, want %+v", after, err, before)
				}
			})
		}
	}
}

func TestHostingInventoryMultipleRootsAreComplete(t *testing.T) {
	withInventoryPanel(t, platform.PanelNone)
	withAccountRoots(t, "/home", "/home2", "/home")
	withMockOS(t, &mockOS{readDir: func(name string) ([]os.DirEntry, error) {
		switch name {
		case "/home":
			return []os.DirEntry{dirEntry("bob", true), dirEntry("alice", true)}, nil
		case "/home2":
			return []os.DirEntry{dirEntry("carol", true), dirEntry("alice", true)}, nil
		default:
			return nil, os.ErrNotExist
		}
	}})
	snap, err := HostingInventory()
	want := HostingSnapshot{Accounts: []string{"alice", "bob", "carol"}, Domains: map[string]string{}}
	if err != nil || !reflect.DeepEqual(snap, want) {
		t.Fatalf("HostingInventory = %+v %v, want %+v", snap, err, want)
	}
}

func TestHostingInventoryEmptyRootPreservesOtherAccounts(t *testing.T) {
	withInventoryPanel(t, platform.PanelNone)
	for _, roots := range [][]string{{"/home", "/home2"}, {"/home2", "/home"}} {
		withAccountRoots(t, roots...)
		withMockOS(t, &mockOS{readDir: func(name string) ([]os.DirEntry, error) {
			switch name {
			case "/home":
				return nil, nil
			case "/home2":
				return []os.DirEntry{dirEntry("alice", true)}, nil
			default:
				return nil, os.ErrNotExist
			}
		}})
		snap, err := HostingInventory()
		want := HostingSnapshot{Accounts: []string{"alice"}, Domains: map[string]string{}}
		if err != nil || !reflect.DeepEqual(snap, want) {
			t.Fatalf("roots %v: inventory = %+v %v, want %+v", roots, snap, err, want)
		}
	}
}
