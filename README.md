# Vulman

<p align="center"> ❤️ Made with love by <b>Human, Codex, Claude</b> in Tokyo.</p>

**Vulnerability Management for your projects.** Vulman is a native desktop application written in Go. It includes an encrypted local database and supports English and Japanese. The interface is embedded in the executable and runs in the operating system's WebView.

## Run

To build from source, install Go 1.26 or later and the [Wails platform dependencies](https://v3.wails.io/getting-started/installation/). Windows uses WebView2. Linux uses GTK4 and WebKitGTK 6.0. The bundled interface needs no npm build or Node.js runtime.

From the repository root:

```sh
go run -tags production ./cmd/vulman
```

You can also run `make build` to create `dist/vulman` (`dist/vulman.exe` on Windows). Open the executable to launch the desktop window. Keep Vulman open for scheduled assessments.

On macOS, run `make release-macos` to build `dist/Vulman.app`. Open it in Finder or run `open dist/Vulman.app`.

```sh
go run -tags production ./cmd/vulman --data-dir ./data --sample
```

- `--sample` adds a sample project to an empty database.
- `--data-dir` opens or creates the workspace at the specified path.

## First assessment

1. Select **Add project**, give it a name, and optionally add a description and repository URL.
2. Register your languages, databases, container images, Docker, web servers, AI tools, and OSS libraries with exact versions.
3. Add an exact **CPE 2.3** identifier for precise NVD queries. Its version field must equal the registered component version. For example: `cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*`.
4. For OSV, supply the ecosystem's canonical package name and ecosystem, then enable OSV in **Configuration**. Examples: `org.apache.logging.log4j:log4j-core` / `Maven`, `django` / `PyPI`, `golang.org/x/net` / `Go`.
5. Select **Sync now**. Findings are ordered by severity and carry their match type, source provenance, original references, and any published fixed-version boundaries.
6. Open an advisory to see public remediation guidance. After applying a verified fix yourself, edit the registered version and CPE and sync again.

The optional **sample project** creates only an example inventory. Its vulnerabilities are fetched from real sources when you choose to sync; no mock findings are shipped.

To extend an existing project's inventory, open its **Tech stack** tab and choose **+ Add component**. Enter the component's category, name, exact version, and optional ecosystem/CPE in the component dialog, then save. Existing components and project settings are preserved. The project is marked as changed until reassessed. Adding components is unavailable while the project is syncing. Each component card also shows its **Critical** finding count, including zero, using the current saved findings for that project and component. Counts update after syncs and are independent of vulnerability display filters.

### Sync by tech stack

The project's **Sync by tech stack** selector defaults to **Everything**. Choose a registered component (shown by category, name, and version) to reassess just that component, or use **Sync now** on its card in the Tech stack tab.

A component sync queries the enabled vulnerability databases for that component and updates only its findings. Other components and repository-scanner findings are preserved. If the component assessment fails or is incomplete, its previous findings are also retained. Activity records the selected component and the number of findings in that assessment.

Repository scanners run with **Everything**, **Sync all projects**, scheduled assessments, and the project's **Scan code** button. Component-only syncs leave the full-project last-complete timestamp, assessed inventory revision, and next scheduled assessment unchanged. Scheduled assessments continue to cover everything.

### Sync by severity

The **Sync by severity** selector defaults to **All severities**. Choose **Critical**, **High**, **Medium**, **Low**, or **Unrated** for a project sync or **Sync all projects** on the Overview and Vulnerabilities pages. Project syncs can combine severity with a selected tech stack and any sync mode. Each component card in the Tech stack tab has its own **Sync by severity** selector, defaulting to **All severities**. Its **Sync now** button uses that card's selection with normal sync mode. Card selections are independent of the project-level selector and other cards, and are retained during navigation and background updates for the current app session. Display filters remain independent of sync selections.

A severity-specific sync updates matching findings and preserves findings at other levels. Previously selected advisories whose rating changes are reconciled, so a downgrade updates the advisory rather than hiding it. Failed or incomplete assessments retain previous findings. Workflow panels and Activity identify the selected severity and its result count.

Shared cache entries always retain all severities. NVD/OSV queries and repository scanners may retrieve broader results; the selection scopes the assessment and reduces CVE record enrichment to selected findings and previously selected advisories whose rating changed. It does not guarantee a smaller database download.

Severity-specific syncs leave the full-project last-complete timestamp, assessed inventory revision, source-data timestamp, and next scheduled assessment unchanged. Scheduled assessments continue to cover all severities.

### Filter findings by tech stack

Both a project's **Vulnerabilities** tab and the left-side **Vulnerabilities** view include a **Tech stack** filter, defaulting to **All tech stacks**. Select a component to show only its findings, combined with the existing search, severity, and match filters.

The global view includes project names in the option labels. Its project filter narrows the options and clears an incompatible selection. Code scanner options represent registered repository URLs and local folders. Select a scan location to see counts for every severity across its findings that match your search and match-type filters. The severity filter narrows the table rows. Use the **Code scanner** match filter to review older findings whose scan location was unavailable.

Both views show a live result count above the list, such as **Showing 3 of 12 vulnerabilities**, including zero matches. The project's tab compares against all findings in that project; the global view compares against findings across all projects. The count updates for search, tech stack, severity, project, and match-type filters.

Both views render up to **100 findings per page**. Filtering and severity ordering apply across the full result set. The count shows the current range, matching findings, and the total when filtered. Changing a filter returns to the first page.

### Live sync workflow

While a sync runs, a compact workflow panel shows the current database/component, elapsed time, and finished-step count. **Show more** expands a vertical stepper and timestamped workflow logs; **Show less** collapses it. Full-project and component-only syncs show only the work included in that run. “Sync all projects” shows a panel for each running project.

Use **Pause** to wait at the next checkpoint between database requests (including paginated requests), CVE records, scanner commands, or final saving. A request or scanner already in progress is allowed to finish; **Pausing** changes to **Paused** when the checkpoint is reached. **Resume** continues the same run with the same scope and in-memory progress. Paused time is excluded from elapsed active time and the 20-minute assessment budget. Paused projects stay locked against overlapping syncs and inventory edits. Pause does not survive an application restart: an unfinished run is recovered as interrupted.

Use **Stop** to cancel the current run, including a paused run. After confirmation, active database requests and scanner process trees are cancelled and the workflow finishes as **Stopped**. Unsaved assessment results are discarded; previously saved findings and full-project freshness stay unchanged. Complete responses already added to the shared cache remain reusable. Stop applies to this run only; future scheduled assessments remain enabled, and you can start a new manual sync after stopping finishes. Controls address an exact run, so an outdated page cannot stop a newer assessment. Each project's workflow can be controlled separately, including runs started by **Sync all projects** or the scheduler.

After a run finishes, use the **×** button to close its workflow panel on the project page. Finished, partially completed, failed, interrupted, and stopped runs can be dismissed. The run remains available in **Activity**, and the next sync displays a new panel. Dismissal lasts for the current app session and survives navigation and background updates.

To permanently remove an interrupted, partial, failed, or stopped entry, choose **Delete activity** beside it in Activity, the project's Activity tab, or the recent Activity list. Confirmation removes that entry and its workflow logs from the local database. Project inventory, vulnerability findings, cache data, freshness timestamps, and schedules remain unchanged. Active (including paused) and successfully completed assessments cannot be deleted. An older incomplete entry can be deleted while a new assessment runs.

Steps cover NVD/OSV queries per component, CVE record enrichment, optional code scanning, and saving results. NVD rate-limit waits and database pagination are visible. The progress bar counts finished steps; it is not an estimated percentage of time remaining. Failed/interrupted steps keep their status even after the bar reaches the end.

The interface polls every two seconds while visible. A version check skips decoding and sending unchanged workspace data while continuing to update cache metrics. Progress-only updates preserve active filters and expanded panels. Completed workflows remain in the project's latest-run panel and in **Activity**. The most recent 200 log events per run are retained in the encrypted database. Interrupted workflows are recovered on restart. English and Japanese UI labels are available; upstream errors retain their original text.

## Sources and matching

| Source | Default | Behavior |
| --- | --- | --- |
| NIST NVD | Enabled | Queries the CVE API 2.0 using exact CPE + `isVulnerable`, or name search when no CPE is supplied. Handles pagination and CVSS severity. |
| CVE Program | Enabled | Retrieves original CVE JSON records for CVE IDs discovered by NVD or OSV, adding CNA titles and CNA/ADP references. |
| OSV.dev | Disabled | Queries exact ecosystem/package/version tuples, follows pagination, skips withdrawn advisories, and collects package-specific fix boundaries. |

NVD and OSV discover matching advisories, and CVE enriches their records. At least NVD or OSV must remain enabled. NVD and OSV are queried on demand. The default CVE endpoint also supports a shared local catalogue built from official bulk downloads. Source endpoints are configurable HTTPS URLs.

**Match types matter:**

- **Package version**: OSV returned the advisory for the registered package/version.
- **CPE match**: NVD returned the advisory for the exact registered CPE. Deployment/environmental conditions still need checking.
- **Needs review**: name-only NVD candidate. The installed version has **not** been verified as affected. These candidates are included in finding counts and can be filtered separately.
- **Code scanner**: a configured external scanner reported the issue. Some scanner reports identify affected version ranges rather than exact installed versions.

Missing severity data is displayed as **Unrated**, never as a low-risk result. OSV uses explicit severity labels supplied by its records; CVSS vector-only records currently remain unrated unless enriched by NVD.

NVD requests are paced globally: approximately one request per 6.1 seconds without a key, or 650 milliseconds with a key. OSV and CVE requests use separate conservative queues. Upstream errors and rate limits are recorded in the assessment history. Normal sync starts a new assessment and reuses fresh cached results.

If any source/scanner fails, the assessment is marked partial or failed and **previous findings are retained**. This can leave resolved findings visible until a complete assessment succeeds. The last complete assessment and inventory revision remain available, and edits mark the inventory stale. A complete result only covers the registered inventory and enabled tools; it is not a claim that a project has no vulnerabilities.

## Shared local cache and sync modes

Vulnerability query results and CVE enrichment records are shared across projects, encrypted in dedicated buckets inside `vulman.db`, and preserved across application restarts. Query identities include the source endpoint, component/package identity, exact version, ecosystem, CPE, and matching-schema version. Cache entries do not store project IDs, and results are attached to the requesting project's component when reused. Changing a version or source endpoint selects a different entry.

The **Sync mode** selector on a project offers:

| Mode | Behavior |
| --- | --- |
| Normal sync | Use fresh cached data; query upstream only for missing/expired entries. Used by scheduled syncs, component-card sync buttons, and Sync all projects. |
| Reassess from cache | Make no vulnerability-database requests and skip repository scanners. Missing data is reported explicitly; expired data is labeled stale and the run remains incomplete. Skipping configured code scanners also makes the run incomplete. |
| Force refresh | Bypass fresh cache entries and fetch upstream, while still respecting rate limits, cooldowns, and concurrent lookup sharing. |

**Configuration → Shared local cache** controls freshness from 1–168 hours; the default is **6 hours**. Empty query results expire after at most **1 hour**, so a previous “no findings” result is periodically rechecked. Refreshes occur on demand during assessments; Vulman does not run a separate full-database mirror updater.

Only complete, successful queries are cached. Incomplete pagination, authentication errors, and failed requests never replace a successful entry or advance its source-check timestamp. When an upstream refresh fails, an existing entry can be used as a clearly marked fallback, with the assessment left incomplete and previous findings retained. Rejected CVE records invalidate their cached enrichment.

Concurrent identical lookups share one upstream operation. A cancelled waiting project stops waiting without cancelling the active lookup. If the project performing that lookup is interrupted, waiting projects receive its error and can refresh on a later sync.

The HTTP clients serialize requests per provider and attempt temporary failures at most **three times**. They use exponential backoff with jitter and honor `Retry-After` seconds or HTTP dates. A delay longer than 30 seconds defers the request rather than blocking a run for that wait; the provider-wide cooldown continues to apply to other requests. Permanent errors such as HTTP 401/403 are not retried. These protections apply to Vulman's database clients; external scanners manage their own networking.

Workflow steps identify cache hits, shared lookups, upstream refreshes, stale fallbacks, and retries. **Source data checked** shows the oldest upstream-check timestamp used by the assessment, separately from when the assessment ran. Cache-only reassessment does not postpone the next scheduled sync. Component-only assessments retain the project's last complete assessment metadata.

The cache defaults to **10,000 entries** and **512 MiB** of encrypted entries, with an **8 MiB per-entry limit**. In **Configuration → Shared local cache**, the entry limit can be set from **100–1,000,000**, and the size limit from **16–4,096 MiB**. The freshness setting remains separate. These capacities grow on demand and do not preallocate the configured disk size or change upstream query frequency.

Oldest entries are evicted whenever either limit is reached. Saving a lower limit immediately removes entries as needed; raising it keeps existing entries. Oversized results can still be used by the current assessment but are not cached. These are logical cache limits, not a limit on the full bbolt database file, which also holds project history and can retain freed pages. Reclaiming physical disk space may require database compaction.

Configuration shows current usage, **fresh cache hits**, **cache misses**, **hit rate**, and **capacity evictions**, updated during normal polling without replacing unsaved form values. Hits and misses count logical normal/cache-only lookups; expired or missing data counts as a miss, including when a concurrent lookup is shared. Forced refreshes and internal diagnostic reads are excluded. Explicit invalidation of a rejected CVE is not counted as a capacity eviction.

Metrics start at zero on upgrade and accumulate across clean restarts. Hit/miss counters are buffered in memory and checkpointed during writes and clean shutdown. Capacity evictions and usage counters are updated atomically with the affected cache entries. Routine statistics and cache writes use maintained metadata instead of scanning the cache; older databases with missing counters are repaired once on opening.

### Local CVE catalogue

In **Configuration → Local CVE database**, select **Update CVE database** to initialize `vulman-cve.db` from the official [CVE List V5 release archives](https://github.com/CVEProject/cvelistV5#releases). The first full download can be several hundred MiB and needs additional temporary disk space. Vulman stores the titles, references, modification dates, and publication/rejection states used for enrichment. Project inventory, findings, and credentials remain in `vulman.db`.

Choose **Manual only**, **Hourly**, or **Daily** automatic updates. The default is **Daily**. The initial bulk download starts when you explicitly select the update button. After initialization, updates run while Vulman is open and overdue updates run after restart. An interrupted initial import also resumes automatically when its update schedule is enabled. **Update CVE database** resumes it immediately. **Stop** cancels download/import work and leaves the last committed checkpoint available.

Updates apply each missing hourly release in order, including across UTC day boundaries. If the release history has a gap or the catalogue is over seven days behind, Vulman imports a current baseline and the subsequent hourly releases. A remaining gap is reported as an error. Successful archive checkpoints and the final successful check are persisted separately, so a failed update cannot claim coverage of skipped releases. GitHub release downloads have their own availability and rate limits. Rate-limit errors are shown in Configuration and can be retried later.

Project assessments use indexed CVE-ID lookups against the catalogue. Missing records are fetched individually through the existing paced CVE client and saved in an independent on-demand bucket. These records survive shared query-cache eviction. Record freshness follows the catalogue's hourly/daily interval with one hour of allowance for release publication. Manual-only mode uses a 24-hour interval. An overdue initialized catalogue supplies clearly labeled stale enrichment and leaves the assessment incomplete while its updater catches up. This avoids refreshing thousands of existing records individually. **Force refresh** still fetches individual CVE records directly. Custom CVE endpoints continue using the endpoint-specific shared query cache.

The catalogue uses AES-GCM with the existing `vulman.key`. Its record payloads and import metadata are encrypted. Archive downloads contain public CVE data and are removed after a successful import. A verified download can be reused when resuming an interrupted import. SHA-256 digests and sizes from the official release metadata are checked before importing, and ZIP CRCs are checked while reading individual records. Archive members are read directly without extracting their paths.

bbolt's synchronized transactions stay enabled. Imports commit at most 256 records together with the ZIP position in each transaction. A full baseline is built in an inactive bucket, then activated by one atomic metadata transaction after all records validate. An interrupted baseline leaves the previous catalogue available. Incremental updates can expose individually committed changes while their last fully imported release remains the freshness checkpoint. On reopening, bbolt recovers committed transactions and Vulman resumes from the saved ZIP position. A partially downloaded archive is downloaded again and verified before import resumes.

Readers use short transactions and B+tree lookups. Maintained counters make status polling independent of catalogue size. Cleanup uses cursors in bounded transactions, and obsolete baseline pages become reusable after activation. **Rebuild catalogue** starts a new full import after confirmation and keeps the current catalogue available until replacement succeeds. bbolt can retain freed pages, so rebuilding can reuse disk space without shrinking the physical file.

Configuration shows the catalogue path, record count, size, release timestamp, last update check, download/import progress, and errors. The catalogue has no independent encryption key. Include `vulman-cve.db` with `vulman.db` and `vulman.key` to back up the downloaded data while Vulman is stopped. You can rebuild the catalogue from the public source if it is omitted from a backup.

## Scheduling

Each project has exactly one schedule: **manual only**, **hourly**, **daily**, or **weekly**. These are elapsed intervals, not a particular local time of day. The next run is persisted, and a scheduler checks due projects every 15 seconds. An overdue project is assessed after startup; overlapping assessments for a project are prevented. A full-project normal or forced sync advances its next scheduled run. Cache-only reassessment leaves that schedule unchanged.

**Vulman must remain running for scheduled assessments.** This release does not install a Windows service, systemd service, or operating-system scheduler. Interrupted runs are marked interrupted on restart. The most recent 30 runs are retained per project.

## Public and AI remediation

Public guidance is available without credentials. It shows retrieved fixed-version boundaries when present and otherwise points to original advisory references. A published boundary is not necessarily the correct upgrade for every supported release branch.

To request optional AI advice:

1. In **Configuration**, enter an OpenAI API key and/or a Claude API key.
2. Enter the exact model ID your API account can access; no account-specific model is assumed.
3. Select a provider, open an advisory, and choose **Propose a fix**.

The OpenAI/Codex integration uses the OpenAI **Responses API**, not desktop Codex authentication or a ChatGPT session. Claude uses the **Messages API**. Advice requests send only the selected finding and its advisory metadata; Vulman does not send repository source code to these AI providers. Failed/missing AI credentials fall back to public guidance. Usage can incur API charges. Generated guidance needs human review; Vulman does not apply patches or modify repositories.

## Optional repository scanners

Enable a tool in Configuration, install it on PATH, and explicitly enable **Run configured code scanners** for a trusted project. In **Edit project**, use **Add repository URL** to set one or more HTTPS GitHub.com repository URLs, such as `https://github.com/owner/repository.git`. You can also set a local folder. Vulman scans each configured location separately. Workflow logs and findings identify the repository, and duplicate findings from different tools are merged within each location. If a location fails, Vulman continues with the remaining locations and retains previous findings. Git must be installed. Submodules are not fetched.

Vulman puts shallow clones, scan temporary files, and supported scanner caches in private system temporary storage outside the active Vulman data directory. It removes that workspace when the scan finishes, fails, or is cancelled. After a force quit, Vulman removes abandoned scan files on the next desktop launch or code scan. The database retains vulnerability findings and run metadata. Scanner caches may be downloaded again on later scans.

For a private repository, enter a **GitHub personal access token** under **Configuration → API credentials** and save. A fine-grained token can be scoped to the repositories you want to scan with **Contents → Read-only** permission. Add the HTTPS repository URL to your project as usual. Vulman tries the clone anonymously first and retries with the token if needed. Git must support `--config-env` for authenticated clones. [GitHub personal access tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens) · [Git command options](https://git-scm.com/docs/git#Documentation/git.txt---config-envltnamegtltenvvargt)

Selecting a tool in **Configuration → Code scanners** runs a short local help or version command using Vulman’s PATH and account permissions. The result shows whether Vulman could start the tool and provides installation or permission guidance for the running OS. Use **Check again** after fixing an installation or permission issue. Repository access and scan prerequisites are checked during the assessment.

On macOS, Vulman also searches the standard Homebrew and Go installation folders when opened from Finder. It searches the inherited `PATH` first and adds `/opt/homebrew/bin`, `/usr/local/bin`, `/usr/local/go/bin`, and `~/go/bin` for scanner commands and their runtimes. For a custom installation, launch Vulman’s executable from a terminal whose `PATH` includes that tool.

| Tool | Invocation | Scope |
| --- | --- | --- |
| govulncheck | `govulncheck -json ./...` | Go package/code vulnerability analysis; Go toolchain required. |
| npm 7+ | `npm audit --json --ignore-scripts` | npm dependency advisories; requires a lockfile. |
| Composer | `composer --no-plugins --no-scripts --no-interaction audit --locked --format=json` | PHP dependency advisories from the lockfile. |
| pip-audit | `pip-audit --format json --locked .` or `pip-audit --format json --disable-pip --no-deps -r requirements.txt` | Python dependency advisories from repository manifests. |
| Trivy | `trivy fs --format json --scanners vuln --quiet .` | Filesystem dependency vulnerability scan. |
| Snyk CLI | `snyk test --json` | Supported dependency manifests; requires a Snyk token and CLI. |

On Windows, Vulman runs the installed `npm-cli.js` through `node.exe` and `composer.phar` through `php.exe` when npm or Composer uses a standard batch launcher. Keep those files in the standard layout beside their launchers. Native `.exe` launchers on PATH also work.

For Python, install a current [pip-audit release](https://github.com/pypa/pip-audit#installation). Vulman looks at the repository root and uses `pylock.toml` and any `pylock.*.toml` files when present. Otherwise, it uses a standalone `requirements.txt` with exact versions for all dependencies you want audited. pip-audit queries PyPI for advisories without installing dependencies. Findings without severity information appear as **Unrated**.

The built-in scanner integrations cover dependency and reachability vulnerabilities. Vulman runs a fixed set of scanner commands.

### Set up Snyk

1. Install the Snyk CLI on the machine running Vulman and add it to PATH. On macOS with Homebrew, run `brew install snyk/tap/snyk`. On Windows, use the standalone `snyk.exe`. [Snyk CLI installation](https://docs.snyk.io/developer-tools/snyk-cli/install-the-snyk-cli)
2. Copy your API token from Snyk account settings or use a Snyk personal access token. Add it under **Configuration → API credentials → Snyk token**. [Snyk CLI authentication](https://docs.snyk.io/developer-tools/snyk-cli/authenticate-to-use-the-cli)
3. Enable **Snyk** under **Code scanners** and select **Save configuration**. The availability check verifies that Vulman can start the CLI. The token is used when a scan runs.
4. In **Edit project**, configure a GitHub repository URL or local folder, enable **Run configured code scanners**, and save the project. Select **Scan code** to run the configured scanners and see their results in the workflow.

Vulman runs `snyk test --json` to check supported dependency manifests and passes the configured token to Snyk as `SNYK_TOKEN`. A nonempty `SNYK_TOKEN` in Vulman's environment takes precedence over the saved credential. [Snyk test](https://docs.snyk.io/developer-tools/snyk-cli/commands/test)

Scanners use their own network services, caches, and local toolchains. Snyk and other tools can execute ecosystem tooling; only scan repositories you trust. Vulman disables npm lifecycle scripts and Composer plugins/scripts, does not install project dependencies itself, bounds output to 16 MiB, and limits each scanner to three minutes. A full assessment has a twenty-minute limit. Missing tools, unsupported report formats, and scanner failures appear in Activity rather than being treated as a clean scan.

### Run code scanners on their own

On the project page, select **Scan code** after enabling **Run configured code scanners** and setting a repository in **Edit project**. The run uses the configured tools, covers all severities, and appears in the project's workflow panel and Activity. It refreshes scanner findings independently of the CVE, NVD, and OSV assessment. Incomplete scans retain previous scanner findings. The project's assessment date and schedule continue to reflect full-project syncs.

For terminal or CI use, build the standalone CLI with `make build-scan`. The command uses the tools on your shell's `PATH`, takes the Snyk token from `SNYK_TOKEN`, and uses `GITHUB_TOKEN` for private GitHub repositories. It runs independently of the desktop workspace and writes a JSON report to stdout.

```sh
./dist/vulman-scan --scanners govulncheck,trivy --dir /path/to/project
./dist/vulman-scan --scanners npm --repo https://github.com/your-org/project.git
./dist/vulman-scan --scanners pip-audit --dir /path/to/python-project
```

Use `--dir` for a local folder or `--repo` for an HTTPS GitHub.com repository URL. With neither option, Vulman scans the current directory. The exit code is **0** for a completed scan with zero findings, **1** for a completed scan with findings, or **2** for invalid arguments or an incomplete scan. The report includes per-tool outcomes, finding counts, findings, and warnings.

## Local storage and credentials

The embedded OSS database is [bbolt](https://github.com/etcd-io/bbolt), linked into the Go executable with no separate database service. State is encrypted with AES-256-GCM. The data directory contains:

- `vulman.db`: projects, inventory, findings, assessment history, configuration, encrypted credentials.
- `vulman-cve.db`: shared encrypted CVE catalogue, on-demand records, and resumable import metadata.
- `vulman.key`: the encryption key. **Back up both files together while Vulman is stopped.** Losing the key makes the database unreadable.

**Configuration** displays the active data directory and the absolute paths to both files beneath the local-storage note.

Normal quit, `kill` (SIGTERM), and Ctrl+C stop active assessments and wait for their final writes before closing bbolt. Force Quit and `kill -9` can end the process immediately. bbolt's synchronized transactions protect committed data, and Vulman marks unfinished assessments as interrupted on the next launch.

The directory and files use owner-only permissions where supported by the OS. The key sits alongside the database; encryption does not protect against another process running as your user or an attacker who obtains both files. Apply normal OS access controls, particularly Windows directory ACLs.

Use the eye button to review a new entry or show a masked preview of a saved key. Saved previews show the first 10 and last 4 characters with `x` in between. Keys with 14 or fewer characters stay fully masked. Blank fields preserve stored values. **Remove stored key** removes a key when Configuration is saved. The following environment variables override stored credentials:

```text
NVD_API_KEY
OPENAI_API_KEY
ANTHROPIC_API_KEY
SNYK_TOKEN
GITHUB_TOKEN
```

## Desktop security

Vulman's bundled interface calls Go through the Wails bridge without opening a local network port. Remote integrations use outbound connections. Repository and advisory links open in the system browser.

## Existing workspaces

Every build defaults to `Vulman` inside your OS user configuration directory. On macOS this is `~/Library/Application Support/Vulman`. On Windows it is `%AppData%\Vulman`. On Linux it is `$XDG_CONFIG_HOME/Vulman` when set, or `~/.config/Vulman` otherwise.

In **Configuration**, browse for or enter an existing workspace directory that contains both `vulman.db` and `vulman.key`, then select **Use this folder**. Vulman switches workspaces immediately and remembers the choice for future launches. Switching loads the selected workspace’s saved configuration and stops active assessments in the previous workspace.

Vulman checks that both files exist and the database decrypts with the supplied key. If the selected or remembered workspace is empty, corrupted, or unavailable, Vulman uses the default directory and shows a warning. **Use default** resets the choice. The `--data-dir` flag overrides the saved choice for a single launch and can initialize a new workspace. Close any other Vulman process using the same database before opening it.

## Development and builds

```sh
make test
make check
make build
```

Use `node --test scripts/test-ui.cjs` for the UI behavior tests. These tests need no npm dependencies.

### UI translations

Each language has a JSON file under `cmd/vulman/locales`. To add a language, copy `en.json` to a file named for its language tag, such as `pt-BR.json`. Set `name` to the label shown in the dropdown, then translate the values under `messages`. Keep message keys and placeholders such as `{count}` intact. The optional `locale` field controls number and date formatting. Remove it to use the filename’s language tag for formatting.

Rebuild Vulman to bundle the file. Both language dropdowns pick it up automatically, and missing messages use the English version.

`make release` builds the desktop app and standalone scanner for Linux and Windows on amd64 and arm64. When run on a Mac, it also builds `dist/Vulman.app` and `dist/vulman-scan-macos`. Check the platform dependencies on the machine that will run the build.

`make release-windows` builds the Windows executables with the Vulman icon embedded. `make release-linux` builds the Linux executables and copies the desktop entry and SVG icon into `dist/`.

To add Vulman to a Linux application menu, install the executable, desktop entry, and icon for your account. Use `vulman-linux-arm64` in the first `install` command on ARM64.

```sh
data_dir="${XDG_DATA_HOME:-$HOME/.local/share}"
install -Dm755 dist/vulman-linux-amd64 "$HOME/.local/bin/vulman"
install -Dm644 dist/com.vulman.app.desktop "$data_dir/applications/com.vulman.app.desktop"
install -Dm644 dist/com.vulman.app.svg "$data_dir/icons/hicolor/scalable/apps/com.vulman.app.svg"
```

The launcher looks for `vulman` on the desktop session's `PATH`. If needed, set `Exec` in the installed desktop entry to the absolute executable path. [Desktop Entry Specification](https://specifications.freedesktop.org/desktop-entry/latest/)

`make release-macos` builds the macOS bundle and standalone scanner. Run it on a Mac with the Xcode Command Line Tools installed. Both builds are universal for Apple Silicon and Intel. The desktop bundle targets macOS 13 or later. The target applies ad-hoc signatures for local use. Distribution to other users can use Developer ID signing and notarization. [Wails macOS packaging guide](https://v3.wails.io/guides/build/macos/)

The macOS and Linux release targets use `cmd/vulman/ui/icon.svg` directly. If the artwork changes, regenerate the embedded Windows resources on macOS with the same SVG renderer.

```sh
mkdir -p dist/windows-icon
swift packaging/macos/render-icon.swift cmd/vulman/ui/icon.svg dist/windows-icon
(cd packaging/windows && go run . ../../dist/windows-icon/icon_256x256.png ../../cmd/vulman)
```

## Project layout

```text
cmd/vulman/           Wails launcher, workspace operations, native bridge, embedded UI
internal/model/      inventory, findings, validation, defaults
internal/store/      encrypted embedded bbolt storage
internal/cvedb/      encrypted CVE catalogue and resumable official release imports
internal/sources/    NVD, CVE, OSV HTTP clients and normalization
internal/engine/     asynchronous assessments and persisted scheduling
internal/scanner/    fixed scanner commands and report adapters
internal/remediation/ public and optional AI guidance
```

## Primary references

- [NVD vulnerability API](https://nvd.nist.gov/developers/vulnerabilities)
- [CVE Services documentation](https://cveawg.mitre.org/api-docs/), [official CVE JSON distribution](https://github.com/CVEProject/cvelistV5)
- [OSV query API](https://google.github.io/osv.dev/post-v1-query/)
- [OpenAI Responses API](https://developers.openai.com/api/reference/resources/responses/methods/create)
- [Claude Messages API](https://platform.claude.com/docs/en/api/messages/create)
- [Composer audit](https://getcomposer.org/doc/03-cli.md#audit), [npm audit](https://docs.npmjs.com/cli/v8/commands/npm-audit/), [Snyk test](https://docs.snyk.io/developer-tools/snyk-cli/commands/test)

## Give a Star! ⭐

If you like or are using this project, please give it a **star**. Thanks!
