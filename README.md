ChainGuard
Evidence-first software supply-chain security analysis
ChainGuard analyzes supported software project manifests and dependency information, correlates package versions with vulnerability intelligence, evaluates source-level reachability where supported, identifies suspicious or known-malicious package signals, and produces machine-readable reports with supporting evidence.
The central design principle is that a vulnerability match is not the same as exploitability. ChainGuard keeps dependency advisories, reachability evidence, package-trust signals, and incomplete checks distinct so a reviewer can understand what was found and why.
> **Project status:** ChainGuard is under active development. Feature availability depends on the checked-out revision and configured environment. Review the limitations section before relying on results for a production security decision.
Contents
What ChainGuard does
Architecture
Supported inputs and ecosystems
Requirements
Install and run the engine
Run a scan
Run the API and dashboard
Security intelligence
Reports and artifacts
Understanding findings
Tests and verification
Configuration and security
Known limitations
Roadmap
Security disclosure
What ChainGuard does
The platform is designed to connect dependency-level security intelligence with evidence from the application being scanned.
Dependency identification: reads supported dependency declarations and project metadata.
SBOM generation: produces a CycloneDX software bill of materials where supported by the current engine workflow.
Vulnerability lookup: queries OSV.dev for package/version advisories and uses a persistent cache where enabled.
Reachability analysis: evaluates whether affected functionality appears reachable in supported source files. This is static analysis, not a proof of exploitability.
Suspicious-package signals: flags packages that meet the engine's suspicious-package rules. Suspicion is not proof of maliciousness.
Known-malicious intelligence: the current development implementation can store known-malicious package records separately from ordinary vulnerability advisories and emit them in `intel.json`.
Evidence and traceability: preserves scan evidence and trace artifacts for investigation.
VEX output: produces OpenVEX output as part of the existing engine workflow.
API and dashboard: provides an API and web interface for initiating scans and reviewing available results and artifacts.
ChainGuard does not use an ML risk score as the authority for security verdicts. Deterministic engine results and traceable evidence remain the basis of findings.
Architecture
At a high level, the scan flow is:
```text
Project path
    |
    v
Dependency / manifest parsing
    |
    v
SBOM generation and package identity
    |
    v
OSV lookup + cached intelligence
    |
    v
Reachability analysis and package-trust signals
    |
    v
Evidence, summary and VEX artifacts
    |
    v
API / dashboard / artifact review
```
The main responsibilities are deliberately separated:
Layer	Responsibility
Engine	Security analysis and findings; it is the authority for security decisions.
API	Request validation, scan orchestration, access control and artifact delivery.
Dashboard	Presents the results and evidence returned by the API. It must not invent or override findings.
Intelligence data layer	Retrieves, caches, normalizes and queries upstream advisory records.
Repository layout
The repository contains multiple components. Their exact nesting can vary between checkouts; inspect the current tree before assuming a path.
Component	Purpose
`software supply chain mvp/chainguard_mvp/`	Python engine, CLI, dependency parsing, OSV client, reachability and report generation.
`software supply chain mvp/tests/`	Engine and intelligence tests.
`ANVATION/chainguard_api/`	API implementation in the monorepo layout that includes the `ANVATION` component.
`ANVATION/tests/`	API and integration tests in that layout.
`frontend/`	Browser UI assets, where present at repository root.
`chainguard_osv_validator.py` or `tools/`	Standalone OSV validation utility, depending on the current revision.
`security_intelligence/` or `chainguard_mvp/intel.py`	Security-intelligence functionality. Use the path present in the checked-out version; avoid maintaining duplicate implementations.
Do not move or rename these components without checking imports, package configuration, tests and documented commands.
Supported inputs and ecosystems
The current engine implementation has been reported to support these dependency inputs:
Ecosystem	Inputs reported as supported
Python / PyPI	Pinned `requirements.txt` declarations and `poetry.lock`
JavaScript / npm	`package.json`
Java / Maven	`pom.xml`
Support is defined by the actual parser and its current implementation—not by the number of ecosystems in an upstream database. Lockfile coverage, transitive dependency resolution, version-range interpretation and source-language reachability can differ by input type.
Unsupported inputs should be reported as unsupported or incomplete. They must not be represented as a clean scan.
Requirements
Use the Python version and dependencies specified by the repository's package metadata and requirements files. The project has been tested with Python 3.11 in the reported development environment; check the current package configuration before choosing a different version.
For the full development workflow, you may also need:
Node.js and npm for frontend checks or builds.
Git for version control.
Network access for live OSV lookups and intelligence refreshes.
Some API and frontend requirements may be separate from the Python engine requirements. Use the component-level dependency files if they exist.
Install and run the engine
Run commands from the repository root unless a command explicitly says otherwise.
1. Install the engine package
The documented installation flow for the engine uses a normal local package install:
```bash
python -m pip install "./software supply chain mvp"
```
If the repository's package directory has been renamed, use the actual path shown by `git ls-files` and its package configuration. Activate the appropriate virtual environment first if you use one.
2. Check the CLI
```bash
python -m chainguard_mvp.cli --help
```
The CLI accepts a project path as its positional target. Common options in the current implementation include:
`--no-llm` — disables the optional LLM-related path, where available.
`--out-dir <path>` — writes scan artifacts to the chosen output directory.
`--fail-on-actionable` — returns a non-zero status when actionable findings or confirmed known-malicious matches are present, according to the current engine implementation.
`--diff` — enables the supported diff workflow.
`--dashboard` — enables the supported dashboard integration path.
`--intel-db <path>` — selects the intelligence database path in revisions that include this option.
Always confirm option names with `--help`; do not substitute similar-looking flags from older instructions.
Run a scan
Scan the included `test_project` (if it exists in your checkout):
```bash
python -m chainguard_mvp.cli ./test_project --no-llm --out-dir ./scan-output
```
Scan a different project by replacing `./test_project` with a directory accessible to the machine running the engine:
```bash
python -m chainguard_mvp.cli /absolute/path/to/project --no-llm --out-dir ./scan-output
```
On Windows, quote paths that contain spaces. For example:
```powershell
python -m chainguard_mvp.cli "C:\path\to\my project" --no-llm --out-dir "C:\temp\chainguard-scan"
```
Use the actual path and a directory that the current user is authorized to scan. Avoid writing generated results into a project's source tree unless that is intentional.
Exit codes
The reported CLI contract uses:
Exit code	Meaning
`0`	Scan completed without triggering the configured actionable-finding failure condition. This does not prove the project is safe.
`1`	With `--fail-on-actionable`, actionable findings or confirmed known-malicious matches triggered the configured gate. A completed scan can still have valid artifacts.
`2`	Invalid arguments, input or Git reference, according to the current CLI contract.
Confirm the exact contract with the CLI documentation in the version being run. A non-zero exit code does not necessarily mean the scan failed to produce findings; inspect the artifacts and error message.
Run the API and dashboard
The web experience has an API and frontend. The exact launch module and frontend command can vary by checkout, so use the current component README and package scripts rather than guessing an import path.
API
Open the API component directory identified in the repository tree.
Install its documented dependencies in the appropriate environment.
Follow its README's `uvicorn` command and configured host/port.
Check the health endpoint in a browser or with an HTTP client. A healthy local API has previously returned a small JSON response such as `{"status":"ok"}`.
Dashboard
Start the frontend using the command defined by its package scripts or component README.
Configure the API base URL to match the running API instance.
Open the local frontend URL printed by the development server.
Use Settings to inspect API status and configure the access token if the API requires one.
Do not expose a development API to the public internet without appropriate authentication, request limits, path restrictions and deployment review.
Authentication
In token-protected configurations, protected scan, remote and artifact requests require a bearer token. The dashboard's Settings page may hold the token in memory, so a browser reload can require entering it again.
Keep tokens in the approved environment or secret-management mechanism. Never commit them, paste them into issues or screenshots, or place them in URLs.
Input limitations
The dashboard can only scan directories accessible to the scanner process on the server or worker. A local path on a visitor's computer is not automatically available to a hosted server. Direct GitHub URL scanning and user ZIP upload should be treated as unavailable unless the current checked-out code and tests prove otherwise.
Security intelligence
OSV.dev
OSV is the primary source for known open-source vulnerability advisories:
API documentation: https://google.github.io/osv.dev/api/
Advisory browser: https://osv.dev/
The engine queries packages and versions found in actual project input. In revisions that include the intelligence store, live OSV responses are cached in SQLite with a reported 24-hour cache lifetime by default. Failed lookups should be represented as unavailable or stale-cache states, not as a confirmed no-advisory result.
OpenSSF Malicious Packages
Repository: https://github.com/ossf/malicious-packages
Project overview: https://openssf.org/projects/malicious-packages/
The intelligence implementation has imported machine-readable records from upstream data and separated `MAL-*` known-malicious records from ordinary vulnerability findings. In the last reported local run, the importer stored 233,845 records across npm, PyPI and Maven. That is a historical count from a particular source snapshot—not a permanent total or guarantee of current coverage. Run the status command in the current version to obtain the actual current record count and freshness.
The reported imported distribution was:
Ecosystem	Records in the reported local snapshot
npm	222,054
PyPI	11,789
Maven	2
Records from unsupported ecosystems were skipped rather than treated as supported coverage. The source dataset is incomplete by nature and its contents change over time.
Refresh and inspect the intelligence store
The current development implementation exposes refresh/status functionality through the engine intelligence module. Check the actual module's help before running commands:
```bash
python -m chainguard_mvp.intel --help
```
Use the refresh and status subcommands documented by that help output. If your checkout places the intelligence module under a separate package, use that package's documented entry point instead.
The default local SQLite cache has been reported at:
```text
~/.cache/chainguard/intel.sqlite
```
The exact location can be overridden by configuration or CLI options in some revisions. Database files, downloaded archives and scan outputs should be treated as runtime data, not automatically committed to Git.
Known intelligence limitations
The last reported implementation still had important limitations:
Range-only records that could not be evaluated were marked `candidate_range_unevaluated`, not confirmed matches.
The separate `withdrawn/` archive directory was not yet ingested in that version.
A refresh re-downloaded an approximately 314 MB archive; conditional refresh using ETag or Last-Modified was not yet implemented.
The dashboard did not yet display known-malicious findings in that reported version.
Check the current source and status before assuming these limitations have been fixed. An intelligence database record count is not a measure of detection accuracy.
Reports and artifacts
A completed scan may produce the following artifacts, depending on input type and enabled features:
Artifact	Purpose
`report.json`	Main structured findings and summary.
`trace.json`	Evidence and processing trace emitted by the engine.
`sbom.cdx.json`	CycloneDX SBOM describing identified components.
`openvex.json`	OpenVEX output where supported by the scan workflow.
`intel.json`	Separate security-intelligence details, including known-malicious matches and per-package intelligence status in versions that implement it.
Use the actual output directory selected for the scan. When an API scan is used, retrieve artifacts through the API's authorized artifact routes rather than bypassing its access controls.
Do not hand-edit scan results and then present them as genuine engine output. Keep the original artifacts when investigating findings.
Understanding findings
Vulnerability match
An advisory matches a package/version according to the source record and the comparison logic supported by the engine. Review the affected range, advisory reference and remediation details. A matching advisory alone does not show that the vulnerable code is reachable.
Reachable
The engine found evidence consistent with a vulnerable code path being reachable in the supported source analysis. This is evidence for investigation, not proof of successful exploitation.
Unreachable or dismissed
The engine did not find the vulnerable path as reachable under the implemented analysis rules. This is not a guarantee of safety: unsupported syntax, indirect calls, dynamic dispatch, generated code or analysis gaps can cause missed paths.
Known malicious package
The package identity matched a known-malicious intelligence record. This category is separate from ordinary vulnerability advisories and should retain the original `MAL-*` identifier and source reference where available.
Suspicious package
The package meets one or more suspicious-package rules, such as unusual or unverified package signals. Suspicious does not mean confirmed malicious. Review the evidence and verify the package provenance independently.
Unavailable or inconclusive
A network error, unsupported ecosystem, unresolved version range or missing source evidence prevented a reliable conclusion. This must not be interpreted as a clean result.
Tests and verification
Run the project's tests from the repository root using the current checked-out configuration:
```bash
pytest -q
```
The monorepo has previously supported component-specific commands such as:
```bash
pytest ANVATION/tests -q
pytest "software supply chain mvp/tests" -q
```
If a component directory has moved, use the actual path. Run the integration test only when its required environment and external services are available. The documented integration flow in the reported version was:
```bash
CHAINGUARD_RUN_INTEGRATION=1 pytest -q -m integration
```
These are test invocation examples, not claims that tests have passed in your environment. Record the actual test counts, skips and exit codes for each run. Some tests require network access to OSV or other upstream services.
Configuration and security
Do not commit `.env` files, tokens, passwords, private keys, private worker credentials or real production data.
Keep `.env.example` restricted to safe placeholders.
Keep local scan outputs, generated archives, SQLite runtime databases, caches, virtual environments and build products out of version control unless a specific file has been reviewed and intentionally approved for publication.
Use path confinement and allowed-root restrictions when accepting project paths.
Do not execute untrusted project code, dependency install scripts or submitted packages as part of a scan.
Enforce API authentication, input limits and timeouts when exposing the API beyond loopback.
Treat package metadata, advisory text and project files as untrusted input.
Review both the current diff and relevant Git history before publishing.
Known limitations
Reachability is heuristic. Source-level analysis does not prove exploitability and may have false positives or false negatives.
Ecosystem support is limited. Only the manifests and source languages implemented by the current parsers are supported.
Dependency resolution is not universal. Transitive dependency graphs, lockfiles and version ranges may be incomplete depending on the project format.
Intelligence is time-sensitive. OSV and malicious-package feeds change, and local caches can be stale.
No advisory does not mean safe. Unknown, newly published, private or unreported malicious packages may not appear in upstream sources.
Suspicion is not proof. Investigate suspicious package signals rather than treating every signal as confirmed malware.
Hosted path scans are server-side. A path on a user's own laptop cannot be scanned by a remote host unless the project is transferred through an implemented and secured workflow.
Persistence depends on deployment. Local SQLite data and scan output may be lost if the host uses ephemeral storage or the runtime directory is cleaned.
Feature status varies by commit. Verify the current dashboard, API routes and intelligence CLI before relying on any feature mentioned above.
Roadmap
Potential next improvements include:
Render `intel.json` and known-malicious matches in the dashboard with protected artifact access.
Complete affected-version evaluation for supported ecosystems and correctly process withdrawn advisories.
Add efficient conditional intelligence refreshes and cache freshness indicators.
Improve reachability analysis and clearly represent unsupported source constructs.
Add secure project-upload support if remote users need to scan projects not already available on the server.
Add reproducible end-to-end checks against genuine projects without treating the test corpus as the runtime intelligence source.
Improve persistence and retention for hosted scan history.
This roadmap is not a claim that these features are already implemented.
Security disclosure
Do not publish a live exploit, private scan artifact, access token or credential in a public issue. Report security-sensitive findings privately to the repository maintainers through the appropriate authorized channel.
License and attribution
Add the project's actual license here once it has been selected and verified. OSV and OpenSSF data have their own source terms, attribution requirements and update characteristics; review those before redistributing snapshots. Do not assume the application license automatically applies to third-party vulnerability data.
---
ChainGuard: security findings should be explainable, traceable and honest about uncertainty.
