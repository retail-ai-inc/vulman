# Vulman

<p align="center"> ❤️ Made with love by <b>Human, Codex, Claude</b> in Tokyo.</p>

**Vulnerability Management for your projects.** Vulman is a native desktop application written in Go. It includes an encrypted local database and supports English and Japanese. The interface is embedded in the executable and runs in the operating system's WebView.

## Download

Download **v1.2.0**, extract the archive, and launch Vulman. No Go installation or compilation is required.

| Platform | Download | Start |
| --- | --- | --- |
| macOS | [Universal ZIP — Apple Silicon + Intel](https://github.com/retail-ai-inc/vulman/releases/download/v1.2.0/Vulman-v1.2.0-macos-universal.zip) | Drag `Vulman.app` into Applications and open it. |
| Windows | [x64](https://github.com/retail-ai-inc/vulman/releases/download/v1.2.0/Vulman-v1.2.0-windows-amd64.zip) · [ARM64](https://github.com/retail-ai-inc/vulman/releases/download/v1.2.0/Vulman-v1.2.0-windows-arm64.zip) | Open `Vulman.exe`. |
| Linux | [x64](https://github.com/retail-ai-inc/vulman/releases/download/v1.2.0/Vulman-v1.2.0-linux-amd64.tar.gz) · [ARM64](https://github.com/retail-ai-inc/vulman/releases/download/v1.2.0/Vulman-v1.2.0-linux-arm64.tar.gz) | Run `./vulman` from the extracted folder. |

Requires macOS 13+, WebView2 Runtime on Windows, or GTK4 and WebKitGTK 6.0 on Linux. See the [release notes](https://github.com/retail-ai-inc/vulman/releases/tag/v1.2.0) for first-launch guidance and [SHA-256 checksums](https://github.com/retail-ai-inc/vulman/releases/download/v1.2.0/SHA256SUMS) to verify your download.

## Build from source

To build from source, install **Go 1.27.3 or later** and the [Wails platform dependencies](https://v3.wails.io/getting-started/installation/). Use the latest stable Go patch release when possible. Windows uses WebView2. Linux uses GTK4 and WebKitGTK 6.0. The bundled interface needs no npm build or Node.js runtime.

Both Go modules declare this minimum. Go may automatically download a compatible compiler when the installed launcher is older; set `GOTOOLCHAIN=local` to require the installed compiler and reject older versions. Downloaded Vulman applications do not require Go to run.

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
5. Select **Match VDBs & Scan Code**. Findings are ordered by severity and carry their match type, source provenance, original references, and any published fixed-version boundaries.
6. Open an advisory to see public remediation guidance. After applying a verified fix yourself, edit the registered version and CPE and reassess.

The optional **sample project** creates only an example inventory. Its vulnerabilities are fetched from real sources when you choose to assess it; no mock findings are shipped.

To extend an existing project's inventory, open its **Tech stack** tab and choose **+ Add component**. Enter the component's category, name, exact version, and optional ecosystem/CPE in the component dialog, then save. Existing components and project settings are preserved. The project is marked as changed until reassessed. Adding components is unavailable while the project is being assessed. Each component card also shows its **Critical** finding count, including zero, using the current saved findings for that project and component. Counts update after assessments and are independent of vulnerability display filters.

### Match by tech stack

Choose **Everything** for a full-project assessment, or use the searchable dropdown to select multiple components, repositories, or both. The action changes to **Match VDBs**, **Scan code**, or **Match VDBs & Scan Code** to match your selection.

Selected-item assessments preserve results for other items. Use **Everything** to refresh the full project's assessment status and schedule. After changing a component version or CPE, reassess it with **All severities** to refresh its counts; previous findings remain until a successful assessment.

### Assess by severity

Choose **All severities** for a complete assessment, or focus on Critical, High, Medium, Low, or Unrated. Component cards have their own severity selector.

Severity-specific assessments preserve other severity levels and do not refresh full-project assessment status. They may still download broader source data. Display filters are separate from assessment selections.

### Filter findings by tech stack

In **Vulnerabilities** or a project's Vulnerabilities tab, select components and repositories in the searchable filter. Combine it with search, severity, project, and match-type filters. Repository choices group dependency findings under their registered repository.

Counts reflect the full matching result set, with **100 findings per page**. Filtering changes the display, not saved results.

### Live assessment workflow

The workflow panel shows progress, elapsed time, and results. **Show more** opens step details, scanner jobs, and logs. Use **Pause**, **Resume**, or **Stop** to control a run; finished runs remain in **Activity**. Progress counts finished steps, not time remaining.

If a required local database is updating, the assessment queues and starts automatically when the update succeeds. If it fails, retry the update, cancel the assessment, or choose **Use available data**. That option skips vulnerability API requests and code scanners and may produce incomplete results.

Stopping a run preserves saved findings. Unfinished runs are marked interrupted after restart. Use **×** to hide a finished panel, or **Delete activity** with confirmation to remove an incomplete run's history without deleting project findings.

## Sources and matching

| Source | Default | Behavior |
| --- | --- | --- |
| NIST NVD | Enabled | Uses the optional indexed local catalogue for CPE and name matching. API 2.0 handles initialization fallback, custom endpoints, forced refreshes, and uncertain applicability. Includes CVSS severity. |
| CVE Program | Enabled | Retrieves original CVE JSON records for CVE IDs discovered by NVD or OSV, adding CNA titles and CNA/ADP references. |
| OSV.dev | Disabled | Uses the selected local ecosystem catalogues when available. Explicit versions and supported semantic-version ranges match locally. Unsupported ranges, missing catalogues, force refresh, and custom endpoints use the existing endpoint-specific cache/API path. |

NVD and OSV discover matching advisories, and CVE enriches their records. At least NVD or OSV must remain enabled. The default NVD, CVE, and OSV endpoints support shared local catalogues built from official bulk downloads, with OSV downloads scoped to selected ecosystems. Missing catalogues, matching rules that require API validation, and custom endpoints use on-demand queries backed by the API response cache. Source endpoints are configurable HTTPS URLs.

**Match types matter:**

- **Package version**: OSV returned the advisory for the registered package/version.
- **CPE match**: NVD returned the advisory for the exact registered CPE. Deployment/environmental conditions still need checking.
- **Needs review**: name-only NVD candidate. The installed version has **not** been verified as affected. These candidates are included in finding counts and can be filtered separately.
- **Code scanner**: a built-in or configured external scanner reported the issue. Some scanner reports identify affected version ranges rather than exact installed versions.

Missing severity data is displayed as **Unrated**, never as a low-risk result. OSV uses explicit severity labels supplied by its records; CVSS vector-only records currently remain unrated unless enriched by NVD.

NVD requests are paced globally: approximately one request per 6.1 seconds without a key, or 650 milliseconds with a key. OSV and CVE requests use separate conservative queues. Upstream errors and rate limits are recorded in the assessment history. Normal assessments reuse local vulnerability data and fresh API responses.

If any source/scanner fails, the assessment is marked partial or failed and **previous findings are retained**. This can leave resolved findings visible until a complete assessment succeeds. Expand the workflow and select a step's **!** button to see its recorded failure reason. The last complete assessment and inventory revision remain available, and edits mark the inventory stale. A complete result only covers the registered inventory and enabled tools; it is not a claim that a project has no vulnerabilities.

## API response cache and assessment modes

Local vulnerability databases supply matching data. The encrypted **API response cache** shares successful fallback and validation responses across projects.

| Assessment mode | Behavior |
| --- | --- |
| **Normal assessment** | Use local databases and fresh cached responses; query APIs when needed. |
| **Reassess from local data** | Use saved data without vulnerability API requests or code scans. Missing, stale, or uncertain data leaves the assessment incomplete. |
| **Force refresh** | Query upstream APIs instead of reusing local results, while respecting rate limits. |

Cache controls are under **Configuration → Advanced settings → API response cache**. Defaults are **6 hours**, **10,000 entries**, and **512 MiB**. **Clear API response cache** requires confirmation and keeps projects, findings, credentials, and downloaded databases.

Background database updates run independently of assessment mode. Failed or incomplete requests do not replace successful cached responses; stale fallbacks are labeled and leave the assessment incomplete.

## Local vulnerability databases

Manage downloads, update schedules, and progress in **Configuration**. Initial downloads can be large; **Daily** updates are the default and run while Vulman is open. Select **More info** in the UI for setup guidance and detailed status.

- Downloads are verified, and atomic checkpoints let interrupted imports resume. A replacement catalogue activates only after validation, keeping the previous catalogue available during rebuilding.
- **Stop** cancels update work and keeps committed progress; the database's **Update** button resumes it. **Rebuild catalogue** starts a replacement after confirmation.
- Overview warns when active data is **more than 7 days old**, even with automatic updates enabled. The warning links to Configuration and can be dismissed.
- Paths appear under **Configuration → File & Databases**. Back up the databases and `vulman.key` together while Vulman is stopped.

### Local CVE catalogue

Select **Update CVE database** to download the official [CVE release archives](https://github.com/CVEProject/cvelistV5#releases) into `vulman-cve.db`. Subsequent updates apply hourly changes. Choose **Manual only**, **Hourly**, or **Daily**. The catalogue enriches discovered CVE IDs with original records.

### Local NVD database and CPE dictionary

Select **Update NVD database** to download [NVD feeds](https://nvd.nist.gov/vuln/data-feeds) and the CPE dictionary into `vulman-nvd.db`. Choose **Manual only**, **Every two hours**, or **Daily**. Name-only matches still need review; uncertain applicability may require API validation.

### Local OSV database

Enable **OSV.dev**, select ecosystems under **Local OSV database**, and **Save configuration**, then select **Update OSV database**. Only selected [ecosystem exports](https://google.github.io/osv.dev/data/) are downloaded to `vulman-osv.db`. Choose **Manual only**, **Hourly**, or **Daily**. Deselected ecosystems stay stored but stop updating. External code scanners use their own advisory services.

## Scheduling

Each project has exactly one schedule: **manual only**, **hourly**, **daily**, or **weekly**. These are elapsed intervals, not a particular local time of day. The next run is persisted, and a scheduler checks due projects every 15 seconds. An overdue project is assessed after startup; overlapping assessments for a project are prevented. A full-project normal or forced assessment advances its next scheduled run. Reassessment from local data leaves that schedule unchanged.

**Vulman must remain running for scheduled assessments.** This release does not install a Windows service, systemd service, or operating-system scheduler. Interrupted runs are marked interrupted on restart. The most recent 30 runs are retained per project.

## Public and AI remediation

Public guidance is available without credentials. It shows retrieved fixed-version boundaries when present and otherwise points to original advisory references. A published boundary is not necessarily the correct upgrade for every supported release branch.

To request optional AI advice:

1. In **Configuration**, enter an OpenAI API key and/or a Claude API key.
2. Enter the exact model ID your API account can access; no account-specific model is assumed.
3. Select a provider, open an advisory, and choose **Propose a fix**.

The OpenAI/Codex integration uses the OpenAI **Responses API**, not desktop Codex authentication or a ChatGPT session. Claude uses the **Messages API**. Advice requests send only the selected finding and its advisory metadata; Vulman does not send repository source code to these AI providers. Failed/missing AI credentials fall back to public guidance. Usage can incur API charges. Generated guidance needs human review; Vulman does not apply patches or modify repositories.

## Optional repository scanners

Enable tools in Configuration and explicitly enable **Run configured code scanners** for a trusted project. External tools need to be installed on PATH; the built-in PHP lockfile scanner needs no PHP or Composer runtime. In **Edit project**, add HTTPS GitHub.com repository URLs or a local folder. Vulman scans each location separately, identifies it in results and logs, and merges duplicate findings within each location. Failed locations retain previous findings. Git is required for GitHub repositories; submodules are not fetched.

### Per-repository scanner profiles

1. Enable installed tools under **Configuration → Code scanners**. **More info** provides installation and permission guidance for your OS; **Check again** rechecks availability.
2. In **Add project** or **Edit project → Code scanning**, set a profile for each GitHub URL and local folder:

   | Target | Modes |
   | --- | --- |
   | GitHub repository URL | **Custom selection** or **Disabled**. Choose tools explicitly before saving. |
   | Local repository folder | **Automatic**, **Custom selection**, or **Disabled**. Automatic detects supported project files. |

3. Enable **Run configured code scanners** and **Save project**. Use **Scan code** to run scanners independently, or include them in a full assessment.

Only globally enabled tools can run. Disabled, skipped, or failed jobs retain their previous findings. The workflow lists each job's status and raw finding count; saved results merge duplicate reports within the same repository and project folder.

| Tool | Checks | Required inputs |
| --- | --- | --- |
| PHP lockfile (local OSV) | PHP dependencies, including development dependencies | `composer.lock` and the downloaded local OSV **Packagist** ecosystem |
| govulncheck | Go vulnerabilities | `go.mod` and a Go toolchain |
| npm audit | JavaScript dependencies | `package.json` and an npm lockfile |
| composer audit | Optional additional PHP dependency audit | PHP/Composer, `composer.json`, and `composer.lock` |
| pip-audit | Python dependencies | Supported Python lockfiles or pinned `requirements.txt` |
| Trivy | Filesystem dependencies | Supported dependency manifests |
| Snyk | Dependencies across supported ecosystems | Snyk CLI and a configured token |

Vulman checks required inputs and reports missing tools or unsupported projects. Selecting **npm audit** or **composer audit** opens **Lockfile options**, where you can enable **Generate missing lockfiles for scanning** (off by default). Reopen the pop-up with the compact **Lockfile options** button when either tool is selected; local Automatic profiles also provide this button when those tools are enabled. It requires the appropriate manifest, preserves existing lockfiles, disables scripts/plugins, and uses a disposable scan copy. Results are labeled because newly resolved versions may differ from deployed dependencies; earlier findings from supplied lockfiles are preserved. Generation may access package registries, but does not install project dependencies.

For PHP, prefer the built-in lockfile scanner: enable OSV.dev, download **Packagist** under **Local OSV database**, and select **PHP lockfile (local OSV)** in the repository profile. Matching stays local and reports unsupported versions as incomplete coverage. It requires an existing lockfile. Composer's optional **Ignore project PHP and extension requirements** setting applies only to temporary lockfile generation; it does not remove Composer's own runtime/network requirements or change existing-lockfile audits.

For **private GitHub repositories**, save a personal access token under **Configuration → API credentials**. Fine-grained tokens need access to the selected repositories with **Contents → Read-only** permission. Use an HTTPS GitHub.com repository URL; authenticated cloning requires Git with `--config-env` support. [GitHub token guidance](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)

Clones, scan temporary files, and supported scanner caches use private system temporary storage outside Vulman's data directory. They are removed after scans; abandoned files from a force quit are cleaned on the next desktop launch or scan. Only findings and run metadata are retained in the database.

### Set up Snyk

1. Install the Snyk CLI on the machine running Vulman and add it to PATH. On macOS with Homebrew, run `brew install snyk/tap/snyk`. On Windows, use the standalone `snyk.exe`. [Snyk CLI installation](https://docs.snyk.io/developer-tools/snyk-cli/install-the-snyk-cli)
2. Copy your API token from Snyk account settings or use a Snyk personal access token. Add it under **Configuration → API credentials → Snyk token**. [Snyk CLI authentication](https://docs.snyk.io/developer-tools/snyk-cli/authenticate-to-use-the-cli)
3. Enable **Snyk** under **Code scanners** and select **Save configuration**. The availability check verifies that Vulman can start the CLI. The token is used when a scan runs.
4. In **Edit project**, configure a GitHub repository URL or local folder, enable **Run configured code scanners**, and save the project. Select **Scan code** to run the configured scanners and see their results in the workflow.

Vulman runs `snyk test --json` to check supported dependency manifests and passes the configured token to Snyk as `SNYK_TOKEN`. A nonempty `SNYK_TOKEN` in Vulman's environment takes precedence over the saved credential. [Snyk test](https://docs.snyk.io/developer-tools/snyk-cli/commands/test)

Scanners use their own network services, caches, and local toolchains. Snyk and other tools can execute ecosystem tooling; only scan repositories you trust. Vulman disables npm lifecycle scripts and Composer plugins/scripts, does not install project dependencies itself, bounds output to 16 MiB, and limits each scanner to three minutes. A full assessment has a twenty-minute limit. Missing tools, unsupported report formats, and scanner failures appear in Activity rather than being treated as a clean scan.

### Run code scanners on their own

On the project page, select **Scan code** after enabling **Run configured code scanners** and setting a repository in **Edit project**. The run uses each repository’s saved scanner profile and globally allowed tools, covers all severities, and appears in the project's workflow panel and Activity. It refreshes scanner findings independently of the CVE, NVD, and OSV assessment. Incomplete scans retain previous scanner findings. The project's assessment date and schedule continue to reflect full-project assessments.

For terminal or CI use, build the standalone CLI with `make build-scan`. External scanners use tools on your shell's `PATH`, `SNYK_TOKEN`, and `GITHUB_TOKEN` for private GitHub repositories. The built-in PHP scanner opens an existing workspace's local OSV database read-only; close the desktop app before using it. All scans write a JSON report to stdout.

```sh
./dist/vulman-scan --scanners govulncheck,trivy --dir /path/to/project
./dist/vulman-scan --scanners npm --repo https://github.com/your-org/project.git
./dist/vulman-scan --scanners pip-audit --dir /path/to/python-project
./dist/vulman-scan --scanners composer-lock --dir /path/to/php-project --data-dir /path/to/Vulman
```

`--scanners` is an explicit tool selection for the CLI target. Manifest-based tools run in detected project folders and report missing inputs. Each scanner job includes its relative `path` and any skip/block `reason` in JSON; the desktop uses the saved per-repository profiles instead.

Add `--generate-lockfiles` to opt into temporary npm/Composer lockfile generation. JSON jobs and findings identify generated-lockfile results; original local files are preserved.
With `--scanners composer --generate-lockfiles`, optionally add `--ignore-composer-platform` to bypass project PHP/extension requirements only during temporary generation.

Use `--dir` for a local folder or `--repo` for an HTTPS GitHub.com repository URL. With neither option, Vulman scans the current directory. The exit code is **0** for a completed scan with zero findings, **1** for a completed scan with findings, or **2** for invalid arguments or an incomplete scan. The report includes per-tool outcomes, finding counts, findings, and warnings.

## Local storage and credentials

The embedded OSS database is [bbolt](https://github.com/etcd-io/bbolt), linked into the Go executable with no separate database service. State is encrypted with AES-256-GCM. The data directory contains:

- `vulman.db`: projects, inventory, findings, assessment history, configuration, encrypted credentials.
- `vulman-cve.db`: shared encrypted CVE catalogue, on-demand records, and resumable import metadata.
- `vulman-nvd.db`: encrypted NVD advisories, CPE dictionary, search indexes, and resumable import metadata.
- `vulman-osv.db`: encrypted ecosystem-scoped OSV advisories, package indexes, pending changes, and resumable import metadata.
- `vulman.key`: the encryption key. **Back up the workspace database and key together while Vulman is stopped.** Losing the key makes the database unreadable.

**Configuration → File & Databases** displays the active data directory and the absolute paths to the workspace database, encryption key, and CVE, NVD, and OSV catalog databases.

Normal quit, `kill` (SIGTERM), and Ctrl+C stop active assessments and wait for their final writes before closing bbolt. Force Quit and `kill -9` can end the process immediately. bbolt's synchronized transactions protect committed data, and Vulman marks unfinished assessments as interrupted on the next launch.

The master database stores settings, project metadata, finding chunks, workflow runs, and log chunks as independently encrypted records. Progress updates touch only the active workflow records. Separate findings and workflow revisions let the interface receive changed records without reloading the workspace or interrupting searches. Records and revisions commit together; incompatible polling cursors safely reload a complete snapshot. Assessment results, severity counts, project changes, and deletions still commit atomically.

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

Existing master databases upgrade automatically on opening. Migration uses one synchronized transaction: an interruption keeps the previous format or the complete new format, and reopening retries an unfinished migration. The key, API response cache, and local vulnerability catalogues are preserved. Older builds cannot open the new format; use a matching database-and-key backup if returning to an older release.

Every build defaults to `Vulman` inside your OS user configuration directory. On macOS this is `~/Library/Application Support/Vulman`. On Windows it is `%AppData%\Vulman`. On Linux it is `$XDG_CONFIG_HOME/Vulman` when set, or `~/.config/Vulman` otherwise.

In **Configuration**, browse for or enter an existing workspace directory that contains both `vulman.db` and `vulman.key`, then select **Use this folder**. Vulman switches workspaces immediately and remembers the choice for future launches. Switching loads the selected workspace’s saved configuration and stops active assessments in the previous workspace.

Vulman checks that both files exist and the database decrypts with the supplied key. If the selected or remembered workspace is empty, corrupted, or unavailable, Vulman uses the default directory and shows a warning. **Use default** resets the choice. The `--data-dir` flag overrides the saved choice for a single launch and can initialize a new workspace. Close any other Vulman process using the same database before opening it.

## Development and builds

```sh
make test
make check
make build
```

Use `make test-ui` for the UI behavior tests; no npm dependencies are needed. Run `make benchmark` for full and incremental encrypted workspace reads, delta payload sizes, focused workflow updates, and full-state updates with allocation and bbolt page metrics, or `make benchmark-ui` for polling, search, and pagination timings with 1,000–50,000 synthetic findings. Benchmarks use disposable data; UI timings run in Node and exclude WebView layout and bridge transfer. Compare runs on the same machine and runtime. To compare an earlier UI snapshot, run `node scripts/benchmark-ui.cjs /path/to/earlier/app.js`.

### UI translations

Each language has a JSON file in `cmd/vulman/locales`. To add one, copy `en.json` to a language-tag filename such as `pt-BR.json`, set `name` and optional `locale`, and translate `messages`. Preserve keys and placeholders such as `{count}` and `{arg0}`.

Rebuild to include the language; missing translations fall back to English. Add translations for structured Go errors as `error_<code>` entries in each locale file.

### Automatic GitHub releases

Update the UI version in `cmd/vulman/ui/index.html` and `CFBundleShortVersionString` in `packaging/macos/Info.plist`, then increment `CFBundleVersion`. Commit and push the changes, including the release workflow and helper scripts, then push a matching tag:

```sh
git tag -a v1.3.0 -m "Vulman v1.3.0"
git push origin v1.3.0
```

GitHub Actions runs the checks and publishes macOS, Windows, and Linux downloads with `SHA256SUMS`. It uses the built-in `GITHUB_TOKEN`; no personal token is needed.

### Platform packaging

Outputs go to `dist/`. `make release` builds Linux and Windows, plus macOS when run on a Mac.

| Platform | Command | Output |
| --- | --- | --- |
| macOS | `make release-macos` | Universal app and scanner; requires a Mac with Xcode Command Line Tools. Ad-hoc signed; see the [signing guide](https://v3.wails.io/guides/build/macos/). |
| Windows | `make release-windows` | x64/ARM64 app and scanner with embedded icons. |
| Linux | `make release-linux` | x64/ARM64 app and scanner, desktop entry, and SVG icon. |

Linux menu integration needs `vulman` on `PATH` and the desktop entry/icon installed for your user. See the [Desktop Entry Specification](https://specifications.freedesktop.org/desktop-entry/latest/).

After changing `cmd/vulman/ui/icon.svg`, regenerate Windows icon resources using the [SVG renderer](packaging/macos/render-icon.swift) and [resource generator](packaging/windows/main.go).

## Project layout

```text
cmd/vulman/           Wails launcher, workspace operations, native bridge, embedded UI
internal/model/      inventory, findings, validation, defaults
internal/store/      encrypted embedded bbolt storage
internal/cvedb/      encrypted CVE catalogue and resumable official release imports
internal/nvddb/      encrypted NVD/CPE catalogue, indexes, matching, and resumable imports
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
