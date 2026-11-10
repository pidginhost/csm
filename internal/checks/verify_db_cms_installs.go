package checks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/pidginhost/csm/internal/mysqlclient"
)

// Re-checks for the non-WordPress CMS findings look at every install of the
// account in the layouts the scanner discovers: the account's public_html and
// each folder directly under its home. Each install is queried with its own
// database login and endpoint, the ones the scanner used. Root on the local
// server could read a same-named schema that is not the install's database.

// cmsInstallLoader reads one discovered config path. isInstall is false when
// the path is not that CMS; an error means the install cannot be inspected.
type cmsInstallLoader func(ctx context.Context, path string) (creds wpDBCreds, isInstall bool, err error)

// cmsVerifyInstalls returns every install of the account, one per database.
// ok is false when the account has none or any of them cannot be read: the
// re-check then cannot vouch for the account and stays unchecked.
func cmsVerifyInstalls(account, rel string, load cmsInstallLoader) ([]wpDBCreds, bool) {
	if !validAccountName.MatchString(account) {
		return nil, false
	}
	home := accountHomeDir(account)
	var paths []string
	for _, pattern := range []string{filepath.Join(home, "public_html", rel), filepath.Join(home, "*", rel)} {
		matches, err := osFS.Glob(pattern)
		if err != nil {
			return nil, false
		}
		paths = append(paths, matches...)
	}
	var installs []wpDBCreds
	seen := map[string]bool{}
	for _, path := range uniqueStrings(paths) {
		creds, isInstall, err := load(context.Background(), path)
		if err != nil {
			return nil, false
		}
		if !isInstall {
			continue
		}
		if creds.dbName == "" || creds.dbUser == "" || (creds.tablePrefix != "" && !validTablePrefix.MatchString(creds.tablePrefix)) {
			return nil, false
		}
		// A linked folder (www -> public_html) names the same database twice.
		identity := creds.dbHost + "\x00" + creds.dbName + "\x00" + creds.tablePrefix
		if !seen[identity] {
			seen[identity] = true
			installs = append(installs, creds)
		}
	}
	return installs, len(installs) > 0
}

// cmsVerifyRecordedInstall returns the install whose database the finding
// recorded. Administrator findings and every PrestaShop finding carry that
// block, so they are re-checked there and nowhere else.
func cmsVerifyRecordedInstall(installs []wpDBCreds, details string) (wpDBCreds, bool) {
	for _, creds := range installs {
		matches := true
		for key, want := range map[string]string{
			"Database": creds.dbName, "Table prefix": creds.tablePrefix, "Database host": creds.dbHost,
		} {
			if got, present := detailFieldPresent(details, key); !present || got != want {
				matches = false
			}
		}
		if matches {
			return creds, true
		}
	}
	return wpDBCreds{}, false
}

// cmsVerifyEveryInstall re-reads the flagged row in each install and resolves
// only when none still classifies. Settings and content findings of Joomla,
// Drupal, Magento and OpenCart do not record their install, so a clean main
// site must not clear a finding an addon site may have raised. query builds
// the statement for one install's table prefix.
func cmsVerifyEveryInstall(installs []wpDBCreds, inPostContext bool, query func(prefix string) (string, error), args ...any) VerifyResult {
	for _, creds := range installs {
		q, err := query(creds.tablePrefix)
		if err != nil {
			return VerifyResult{Checked: false, Detail: "could not validate the tables from the finding"}
		}
		rows, err := runDBVerifyQueryAs(creds, q, args...)
		if err != nil {
			return dbVerifyQueryError()
		}
		for _, row := range rows {
			if _, _, ok := classifyMalwareRow(mysqlclient.BatchUnescape(row), inPostContext); ok {
				return VerifyResult{Checked: true, Resolved: false, Detail: "the flagged row still contains injected content"}
			}
		}
	}
	return VerifyResult{Checked: true, Resolved: true, Detail: "the flagged row no longer contains injected content"}
}

func drupalVerifyInstall(ctx context.Context, path string) (wpDBCreds, bool, error) {
	// public_html is three folders up from sites/default/settings.php.
	matched, err := looksLikeDrupal8Plus(filepath.Dir(filepath.Dir(filepath.Dir(path))))
	if err != nil || !matched {
		return wpDBCreds{}, false, err
	}
	creds, err := parseDrupalSettings(ctx, path)
	if err != nil {
		return wpDBCreds{}, true, err
	}
	return creds.asWPDBCreds(), true, nil
}

func joomlaVerifyInstall(ctx context.Context, path string) (wpDBCreds, bool, error) {
	matched, err := looksLikeJoomlaConfig(ctx, path)
	if err != nil || !matched {
		return wpDBCreds{}, false, err
	}
	creds, err := parseJConfig(ctx, path)
	if err != nil {
		return wpDBCreds{}, true, err
	}
	w := creds.asWPDBCreds()
	if w.tablePrefix == "" {
		w.tablePrefix = "jos_"
	}
	return w, true, nil
}

// magentoVerifyInstall reads one app/etc folder: env.php (Magento 2) first,
// local.xml (Magento 1) only when env.php does not exist. An unsafe or
// unreadable env.php must not select an older, unrelated database.
func magentoVerifyInstall(ctx context.Context, etcDir string) (wpDBCreds, bool, error) {
	creds, err := parseMagentoM2(ctx, filepath.Join(etcDir, "env.php"))
	if errors.Is(err, os.ErrNotExist) {
		creds, err = parseMagentoM1(ctx, filepath.Join(etcDir, "local.xml"))
		if errors.Is(err, os.ErrNotExist) {
			return wpDBCreds{}, false, nil
		}
	}
	if err != nil {
		return wpDBCreds{}, true, err
	}
	return creds.asWPDBCreds(), true, nil
}

func openCartVerifyInstall(ctx context.Context, path string) (wpDBCreds, bool, error) {
	matched, err := looksLikeOpenCart(ctx, path)
	if err != nil || !matched {
		return wpDBCreds{}, false, err
	}
	creds, err := parseOpenCartConfig(ctx, path)
	if err != nil {
		return wpDBCreds{}, true, err
	}
	w := creds.asWPDBCreds()
	if w.tablePrefix == "" {
		w.tablePrefix = "oc_"
	}
	return w, true, nil
}

// prestashopVerifyInstall reads one config/defines.inc.php marker. Staging and
// backup copies are skipped, as the scanner skips them.
func prestashopVerifyInstall(ctx context.Context, marker string) (wpDBCreds, bool, error) {
	root := prestashopRoot(marker)
	if wpSkipDirNames[strings.ToLower(filepath.Base(root))] {
		return wpDBCreds{}, false, nil
	}
	creds, isShop, err := readPrestaShopCreds(ctx, root)
	if err != nil || !isShop {
		return wpDBCreds{}, isShop, err
	}
	return creds.asWPDBCreds(), true, nil
}

func drupalVerifyInstalls(account string) ([]wpDBCreds, bool) {
	return cmsVerifyInstalls(account, filepath.Join("sites", "default", "settings.php"), drupalVerifyInstall)
}

func joomlaVerifyInstalls(account string) ([]wpDBCreds, bool) {
	return cmsVerifyInstalls(account, "configuration.php", joomlaVerifyInstall)
}

func magentoVerifyInstalls(account string) ([]wpDBCreds, bool) {
	return cmsVerifyInstalls(account, filepath.Join("app", "etc"), magentoVerifyInstall)
}

func openCartVerifyInstalls(account string) ([]wpDBCreds, bool) {
	return cmsVerifyInstalls(account, "config.php", openCartVerifyInstall)
}

func prestashopVerifyInstalls(account string) ([]wpDBCreds, bool) {
	return cmsVerifyInstalls(account, filepath.Join("config", "defines.inc.php"), prestashopVerifyInstall)
}
