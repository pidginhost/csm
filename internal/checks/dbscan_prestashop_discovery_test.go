package checks

import (
	"context"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestPrestaShopSuspendedConfigDoesNotMakeScanIncomplete(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	files := prestashopInstallFiles(psTestRoot, "ps_")
	files["/var/cpanel/suspended/alice"] = ""
	files[psTestRoot+"/app/config/parameters.php"] = "<?php return [];"
	withCMSConfigOS(t, &twoOwnerCMSOS{files: files})
	queries := withCapturedQueries(t, psEntryRows)
	ctx, coverage := withIncompleteCheckCollector(context.Background())
	CheckPrestaShopContent(ctx, &config.Config{}, nil)
	if len(*queries) != 0 || coverage.contains(prestashopOwner) {
		t.Fatalf("suspended config scanned: queries=%d incomplete=%v", len(*queries), coverage.contains(prestashopOwner))
	}
}

func TestPrestaShopSuspendedInstallDoesNotConsumeScanLimit(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	files := prestashopInstallFiles(psTestRoot, "ps_")
	files["/var/cpanel/suspended/alice"] = ""
	for path, body := range prestashopInstallFiles("/home/bob/public_html", "ps_") {
		files[path] = body
	}
	withCMSConfigOS(t, &twoOwnerCMSOS{files: files})
	withCapturedQueries(t, psEntryRows)
	ctx, coverage := withIncompleteCheckCollector(context.Background())
	cfg := &config.Config{}
	cfg.Thresholds.AccountScanMaxFiles = 1
	findings := CheckPrestaShopContent(ctx, cfg, newCrontabTestStore(t))
	if len(findings) != 2 || coverage.contains(prestashopOwner) {
		t.Fatalf("active shop scan: findings=%d incomplete=%v", len(findings), coverage.contains(prestashopOwner))
	}
	for _, f := range findings {
		if f.TenantID != "bob" {
			t.Fatalf("scanned suspended tenant %q", f.TenantID)
		}
	}
}

func TestPrestaShopSkipsCopyNamesCaseInsensitively(t *testing.T) {
	for _, dir := range []string{"Staging", "Backup", "Backups", "Cache", ".Trash"} {
		t.Run(dir, func(t *testing.T) {
			withAccountHomeRoots(t, "/home")
			withCMSConfigOS(t, &twoOwnerCMSOS{files: prestashopInstallFiles("/home/alice/"+dir, "ps_")})
			queries := withCapturedQueries(t, psEntryRows)
			ctx, coverage := withIncompleteCheckCollector(context.Background())
			findings := CheckPrestaShopContent(ctx, &config.Config{}, nil)
			if len(findings) != 0 || len(*queries) != 0 || coverage.contains(prestashopOwner) {
				t.Fatalf("copy scanned: findings=%d queries=%d incomplete=%v", len(findings), len(*queries), coverage.contains(prestashopOwner))
			}
		})
	}
}
