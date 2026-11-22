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

Choose **Manual only**, **Hourly**, **Daily**, or **Weekly** per project. **Keep Vulman running** for automatic assessments. Schedules use elapsed intervals; overdue runs start after restart, and assessments for the same project do not overlap.

Full-project normal or forced assessments advance the next run; reassessing from local data does not. Interrupted runs are marked after restart, and the latest 30 runs are retained per project.

## Public and AI remediation

Public guidance needs no API key and provides published fix information or original advisory references.

For optional AI advice, configure an OpenAI or Claude API key and an accessible model ID in **Configuration**. Open an advisory, select a provider, and choose **Propose a fix**. Public guidance remains available if AI is unavailable.

AI requests share only the finding and advisory metadata, excluding repository source code. API charges may apply. Review guidance before applying changes; Vulman does not modify repositories.

## Optional repository scanners

Scan HTTPS GitHub repositories or local folders. External scanners must be on `PATH`; Git is required for GitHub scans, and submodules are not fetched. The built-in PHP lockfile scanner needs no PHP or Composer runtime.

### Per-repository scanner profiles

Enable tools under **Configuration → Code scanners**, then set each location's profile in **Add project / Edit project → Code scanning**. Enable **Run configured code scanners**, save, and select **Scan code**.

| Target | Modes |
| --- | --- |
| GitHub URL | **Custom selection** or **Disabled** |
| Local folder | **Automatic**, **Custom selection**, or **Disabled** |

Automatic detects supported project files. Only globally enabled tools can run.

| Tool | Requires |
| --- | --- |
| PHP lockfile (local OSV) | Existing `composer.lock`; enable OSV.dev and download [Packagist data](#local-osv-database). |
| govulncheck | `go.mod` and a Go toolchain. |
| npm audit | `package.json` and an npm lockfile. |
| composer audit | PHP/Composer, `composer.json`, and `composer.lock`. |
| pip-audit | Supported Python lockfiles or pinned `requirements.txt`. |
| Trivy | Supported dependency manifests. |
| Snyk | Snyk CLI and token. |

Use **Lockfile options** to enable temporary npm/Composer lockfile generation. Original files are preserved and scripts/plugins disabled; resolved versions may differ from deployed dependencies.

For private GitHub repositories, save a PAT in **Configuration → API credentials**. Fine-grained tokens need access to the selected repositories with **Contents → Read-only** permission.

Skipped or failed jobs retain previous findings. Workflow counts are raw reports; saved results merge duplicates within each repository and project folder.

Clones and temporary scan data are removed after scanning; leftovers from force quits are cleaned on the next launch or scan.

### Set up Snyk

1. Install the [Snyk CLI](https://docs.snyk.io/developer-tools/snyk-cli/install-the-snyk-cli) on `PATH`: macOS `brew install snyk/tap/snyk`; Windows `snyk.exe`.
2. Add your [Snyk token](https://docs.snyk.io/developer-tools/snyk-cli/authenticate-to-use-the-cli) under **Configuration → API credentials → Snyk token**.
3. Enable **Snyk** under **Configuration → Code scanners**, then **Save configuration**.
4. In **Edit project**, add a repository or local folder, select **Snyk** in its scanner profile, enable **Run configured code scanners**, and save. Select **Scan code**.

A nonempty `SNYK_TOKEN` overrides the saved token. External scanners use their own services and tools; scan only repositories you trust.

### Run code scanners on their own

**Desktop:** Configure a repository and enable **Run configured code scanners** in **Edit project**, then select **Scan code**. This refreshes scanner findings only; incomplete scans retain previous findings.

**CLI:** Included in release downloads, or build with `make build-scan` to create `dist/vulman-scan` (`.exe` on Windows). It writes JSON to stdout:

```sh
./dist/vulman-scan --scanners govulncheck,trivy --dir /path/to/project
./dist/vulman-scan --scanners npm --repo https://github.com/your-org/project.git
./dist/vulman-scan --scanners composer-lock --dir /path/to/php-project --data-dir /path/to/Vulman
./dist/vulman-scan --help
```

External tools must be on `PATH`. Use `GITHUB_TOKEN` for private GitHub repositories and `SNYK_TOKEN` for Snyk. `composer-lock` requires a workspace with the local OSV Packagist database; close the desktop app before using it.

With no `--dir` or `--repo`, the CLI scans the current folder. See `--help` for scanner names and temporary lockfile options.

Exit codes: **0** = complete with no findings, **1** = complete with findings, **2** = error or incomplete scan.

## Local storage and credentials

Data is stored locally in [bbolt](https://github.com/etcd-io/bbolt) with AES-256-GCM encryption:

- `vulman.db`: projects, findings, assessment history, settings, and credentials.
- `vulman-cve.db`, `vulman-nvd.db`, `vulman-osv.db`: local vulnerability catalogues, including the CPE dictionary.
- `vulman.key`: the encryption key.

View file paths in **Configuration → File & Databases**. **Back up the databases and key together while Vulman is stopped. Losing the key makes the data unreadable.** Encryption does not protect against access through your OS account or possession of both the databases and key.

Writes commit atomically, and unfinished assessments are marked interrupted after restart.

The eye button reveals new input or a masked saved-key preview. Blank fields keep stored credentials; **Remove stored key** takes effect when Configuration is saved.

Environment variables override stored credentials: `NVD_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `SNYK_TOKEN`, `GITHUB_TOKEN`.

## Desktop security

Vulman's bundled interface calls Go through the Wails bridge without opening a local network port. Remote integrations use outbound connections. Repository and advisory links open in the system browser.

## Existing workspaces

Workspaces upgrade automatically with atomic, interruption-safe migrations. Keys, API response cache, and local catalogues are preserved. Returning to an incompatible older build requires a matching backup of the database and key.

To switch, select a folder containing `vulman.db` and `vulman.key` in **Configuration → Use this folder**. The choice is remembered; switching loads its settings and stops active assessments. **Use default** resets the selection, while `--data-dir` overrides it for one launch. Invalid workspaces fall back to the default with a warning.

Default folders: macOS `~/Library/Application Support/Vulman`; Windows `%AppData%\Vulman`; Linux `$XDG_CONFIG_HOME/Vulman` or `~/.config/Vulman`.

Close other Vulman processes using the same database before opening it.

## Development and builds

| Command | Purpose |
| --- | --- |
| `make test` | Go tests with the race detector. |
| `make test-ui` | UI behavior tests. |
| `make check` | Go static checks (`go vet`). |
| `make build` | Desktop executable in `dist/`. |
| `make benchmark` / `make benchmark-ui` | Storage and UI benchmarks. |

`make test-ui` and `make benchmark-ui` require Node.js; no npm dependencies are needed.

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
