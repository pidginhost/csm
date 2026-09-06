# cPanel release tests

Version tags require either a cPanel integration image or a recorded reason for
releasing without one. `release-preflight` runs before builds, and integration
repeats the preflight before allocating servers. The tag-specific publication
dependencies require that integration succeeds; package registry publication,
repository publication and releases cannot use an AlmaLinux/Ubuntu-only result
unless the omission was acknowledged. Main-branch integration remains manual and
may run without cPanel when no image is configured.

## Releasing without cPanel coverage

CSM has no licensed cPanel image while no cPanel licence is available for
disposable CI clones. Set the protected variable `CSM_RELEASE_WITHOUT_CPANEL`
to a sentence stating why, for example `no licensed cPanel image available`.
A bare `1` is rejected: the reason is published in the pipeline log and in
`dist/cpanel-release.json` as `cpanel_coverage: "absent"`.

Do not read such a release as cPanel-tested. WHM plugin installation, mail
integration, cPanel platform paths, service confinement under a real cPanel
layout, and upgrade behaviour are unvalidated in that pipeline, and the
findings that depend on them (F19, F22, F25) stay open. Clear the variable as
soon as an image exists.

The CSM release maintainer owns the CI variables and image refresh schedule.
The PidginHost cloud image administrator owns capture and publication of the
private reusable image. The release maintainer must verify a clone before
setting `INTEGRATION_CPANEL_IMAGE` to its immutable ID or versioned slug.
Do not set it to a base AlmaLinux image: the package test requires a working
cPanel installation and fails if it is absent.

## Image preparation

1. Allocate a dedicated AlmaLinux 9 x86_64 build VM with the CI SSH key.
   The default test plan is `cloudv-2` (8 GB RAM, 80 GB disk); override with
   `INTEGRATION_CPANEL_PACKAGE` if needed. Follow the supported OS, hostname,
   storage and licensing requirements in the
   [cPanel installation guide](https://docs.cpanel.net/installation-guide/system-requirements-almalinux/).
2. Install full cPanel/WHM using the
   [official installer](https://docs.cpanel.net/installation-guide/install/).
   Complete initial setup with EA4 Apache, Exim, Dovecot, rsyslog and a valid
   license arrangement for disposable clone IPs. DNSOnly is insufficient.
   Do not install CSM or create tenant accounts on the image.
3. Verify `systemctl is-active exim dovecot`, `exim -bV`, `doveconf -n`, and
   the WHM AppConfig tools. `/var/log/maillog` must exist. Ensure cloud-init
   preserves a valid cPanel hostname and injects the dedicated CI SSH key
   into the existing `phuser` account with passwordless sudo.
4. Have the cloud image administrator capture the VM using the provider's
   image preparation process. Remove build credentials and tenant data;
   regenerate host keys and machine identity on clones. Record the OS,
   cPanel version, image build date and responsible maintainer in the image
   metadata. Never publish an image containing a customer backup.
5. Publish the private image under an immutable ID or versioned slug and
   verify that the CI account sees it in `phctl compute image list`. The
   current CLI can create VM snapshots but cannot promote them to reusable
   OS images; that step requires cloud image administration access.
6. Set the protected GitLab project variable `INTEGRATION_CPANEL_IMAGE`.
   Run the manual integration job once these checks are on main before
   relying on the image for a tag release.

Refresh the image for cPanel/OS security updates and review it at least monthly.
License activation, SSH injection, empty CSM state and mail service readiness
must work on a new clone, not only on the image-build VM.

## What the release job checks

The cPanel VM starts without CSM. The job downloads the previously released
RPM pinned in `build/integration-upgrade.json` and verifies its SHA-256. It
installs that version, writes operator configuration and a state sentinel,
starts its daemon, then upgrades to the RPM built by the current pipeline.
It checks that configuration, drop-ins and state survive and that the installed
binary has the exact SHA-256 of the current build artifact.

The candidate's package-mode installer is exercised on that cPanel host, and
the service is restarted using its installed unit. Dedicated tests require:

- cPanel and Exim platform detection with existing platform-derived paths.
- Working Exim and Dovecot services and configuration commands.
- Executable WHM CGI, registration reported by the read-only
  [WHM application-list API](https://api.docs.cpanel.net/specifications/whm.openapi/applications/sys-get_appconfig_application_list),
  and the expected redirect.
- A running notify service with strict filesystem protection, healthy state,
  and an attached mail-log watcher.

The ordinary real-system integration suite then runs on that same host and
on the AlmaLinux and Ubuntu hosts. No test sends customer mail; alert delivery
and automatic response are disabled in the integration drop-in. The cPanel
package test only runs with an explicit disposable-server marker and refuses
an image with CSM or its state already present.

Update the baseline pin deliberately after reviewing the released RPM and its
published SHA-256. Never resolve a moving `latest` package during this test.

## Evidence and cleanup

Integration retains cPanel package output, service/journal diagnostics,
baseline and candidate status snapshots, and `cpanel-release.json` for one
year. The JSON identifies the candidate commit, binary/package hashes,
image, plan and upgrade baseline. Its `package_checks` field covers the
package phase; the integration job must also pass the later real-system tests
and verified server cleanup before publication is allowed.

Server IDs are recorded immediately after creation. Verified cleanup runs
before successful completion, with an `after_script` retry for errors or
cancellation. A failed package check retains diagnostics and still reaches
that cleanup. Image preparation and a successful live cPanel job are required
operational steps; compiling the integration binary locally does not replace
them.

The candidate daemon also enables and removes the forward guard through a test
drop-in and service restart. This runs the actual cPanel rebuild through the packaged
service sandbox and checks that removal preserves operator configuration.
