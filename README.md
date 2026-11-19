# MalGuard AI

**Intelligent Malware Detection, Threat Intelligence & Security Analysis**

MalGuard AI is a Streamlit application for checking Windows executable files, protecting files with encryption, reviewing scan history, and exploring defensive security scenarios. It analyzes uploaded files as data and never executes them or probes other computers.

## Features

| Workspace | What you can do |
|---|---|
| Overview | Choose a workflow and review your recent activity |
| Malware Scanner | Check Windows PE executables/DLLs using a trained Random Forest; view file fingerprints, scores and follow-up guidance |
| Threat Intelligence | Filter real scan records and explore detection counts, daily/weekly/monthly trends and file characteristics |
| File Security | Encrypt with AES-256-GCM; decrypt modern AES or legacy AES Crypt files; use explicitly warned DES compatibility |
| Resilience Lab | Measure how model answers change under bounded numerical metadata variations without changing the uploaded file |
| Exposure Simulator | Upload a JSON/YAML environment, explore hypothetical reachability, and compare asset-isolation scenarios |
| Scan History & Reports | Search, compare, download JSON/CSV/text reports, and manage retention or deletion |
| Model Insights | Read the model's measured evaluation results, feature importance and limitations |

The interface uses deep blue (`#09318D`), white (`#FFFFFF`) and bubblegum pink (`#FD91CC`), with responsive layouts and local Lottie illustrations. Animations are decorative, support pause/reduced-motion controls, and can be disabled in the sidebar. They do not represent scan progress.

## Local setup

Requires CPython **3.15**. Run from the repository root in PowerShell:

```powershell
py -3.15 -m venv .venv
# These overrides apply only to this shell, not Windows system settings.
$env:PYTHONPATH = ''
$env:PYTHONHOME = ''
$env:PIP_TARGET = ''
.\.venv\Scripts\python.exe -m pip --isolated install --target .venv\Lib\site-packages -r requirements.txt
.\start.ps1
```

Open **http://127.0.0.1:8501**. Keep the terminal running; press Ctrl+C to stop. If the port is already occupied, stop the previous app or use `./start.ps1 -Port 8502` and open the matching address.

`start.ps1` uses the project interpreter and temporarily clears inherited Python/pip overrides. Activation is optional. Conda and global package installation are unnecessary. For an existing environment, run `./scripts/project.ps1 -PythonArgs @('-m','pip','check')` to check dependencies.

### Troubleshooting the 3000 / 8501 URL mismatch

Port 3000 is Streamlit's frontend development port. An inherited `PYTHONPATH` can load Streamlit from a nonstandard global directory and trigger development mode even when the backend listens on 8501. The project explicitly disables development mode; `start.ps1` also isolates imports. Restart the old process after changing configuration. Do not open port 3000 for this app.

On Linux or another clean host:

```bash
python3.15 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m streamlit run streamlit_app.py
```

## How file analysis works

Upload → size/signature validation → isolated static PE parsing → ordered model features → prediction → interpretation → scoped history → report.

Only Windows PE executable and DLL content can receive a malware classification. Other formats, empty files and malformed containers receive an error, never an automatic legitimate verdict. The default limit is 20 MiB per file and ten files per action. The parser has a 15-second timeout and never launches the upload.

Results distinguish:

- **Prediction:** malware (`0`) or legitimate (`1`). Neither is a complete security assessment.
- **Malware score:** uncalibrated model support for the malware class, not the real-world probability of infection.
- **Review required:** the winning class scored below 80%; this is an uncertainty flag, not a third trained class.
- **Risk category:** High for malware, Review for uncertain legitimate predictions, otherwise Low. These are workflow priorities.
- **SHA-256:** the file's primary fingerprint. MD5 is included only for legacy identification.
- **Entropy:** byte variability on a 0–8 scale. High values can also occur in legitimate compressed/encrypted files.

Keep flagged files closed and seek independent analysis. A legitimate prediction does not establish safety. Private file bytes are not sent to reputation services. The dashboard describes your saved checks, not global attack activity.

## Machine learning

The model uses scikit-learn with authentic data from `datasets/dataset_1.csv` (138,047 original rows). Identifier/hash/label columns and unreliable legacy version-information counts are excluded. Conflicting labels and duplicate hashes/rounded feature vectors are removed before stratified train/validation/test splitting. Training-only preprocessing prevents fitting on evaluation rows.

The retained 104,581 rows are split into 62,748 training, 20,916 validation and 20,917 test rows. Validation malware F1 selects a 128-tree Random Forest over scaled Logistic Regression. Malware (`0`) is the positive class for the metrics below.

| Held-out metric | Result |
|---|---:|
| Accuracy | 99.1873% |
| Malware precision | 99.4142% |
| Malware recall | 99.2413% |
| Malware F1 | 99.3277% |
| False-positive rate | 0.8956% |
| False-negative rate | 0.7587% |
| ROC-AUC | 0.999661 |
| Average precision | 0.999781 |

The confusion matrix, ordered legitimate then malware, is `[[8189, 74], [96, 12558]]`. These are dataset evaluation results, not guarantees for current threats. Malware-family/time metadata is unavailable, so family and temporal generalization remain unverified. Global feature importance describes model associations, not a causal explanation for each file.

`model/manifest.json` records feature order, labels, split seeds, dataset/artifact hashes, versions and complete metrics. Only the trusted packaged model is loaded; uploaded pickle/joblib objects are never deserialized. Original datasets and model artifacts remain for provenance.

To retrain explicitly:

```powershell
.\scripts\project.ps1 -PythonArgs @('model_trainer.py')
```

Retraining replaces only the modern model and manifest. Restart the app afterward. Keep the pinned scikit-learn version consistent between training and hosting; validate and retrain before upgrading it.

## File encryption

Choose **Encrypt → AES-GCM**, enter a strong password, then download the protected file. To reopen it, choose **Decrypt → Auto AES** and use the same password. Forgotten passwords cannot be recovered.

New files use AES-256-GCM, a fresh 16-byte salt, a 12-byte nonce and Scrypt key derivation (`N=32768, r=8, p=1`). The versioned `MG-AES-GCM` header is authenticated along with the ciphertext. Authentication failures return no plaintext. Decryption permits 64 KiB of format overhead beyond the plaintext size limit.

Auto AES also recognizes legacy AES Crypt files. Legacy AES Crypt encryption and DES-ECB/PKCS#7 remain available for compatibility. DES uses the original first-eight-character, zero-padded key convention and requires acknowledgement: it is insecure and unauthenticated, and incorrect keys cannot always be detected reliably.

Passwords and derived keys are never saved in history or logs. Inputs/outputs stay in session memory until replaced, cleared or the session ends. Original local files are never overwritten or deleted.

## Resilience Lab

Scan a file first, select its analysis, then choose metadata dimensions, variation strength, scenario count and seed. The lab changes numeric feature copies only; no executable variants are produced. It supports 1–128 scenarios, strength up to 0.50 and a 15-second evaluation limit.

Stability is `100 × unchanged predictions / scenarios`. A flip means a changed verdict; score deviation measures how far a scenario's score moved from the baseline. Identical seed/settings reproduce the experiment; rounded or bounded scenarios can repeat. These synthetic vectors may not represent realizable executables. Stability is not proof of safety or universal adversarial robustness.

## Exposure Simulator

Use the labeled example or upload a UTF-8 JSON/YAML inventory (maximum 256 KiB). Begin with this complete example:

```json
{
  "hosts": [
    {"id":"workstation","hostname":"analyst-pc","os":"Windows","os_version":"11","zone":"office","criticality":2,
     "applications":[{"name":"Browser","version":"user-supplied"}],"services":[],"controls":["endpoint_protection"]},
    {"id":"files","hostname":"file-server","os":"Windows","os_version":"Server 2022","zone":"servers","criticality":5,
     "applications":[],"services":[{"name":"SMB","port":445}],"controls":["least_privilege"]},
    {"id":"backup","hostname":"backup","os":"Linux","zone":"backup","criticality":5,"controls":["isolated"]}
  ],
  "connections": [{"source":"workstation","target":"files"},{"source":"files","target":"backup"}]
}
```

Required host fields: `id`, `hostname`, `os`, `zone`, and `criticality` (1–5). Other fields above are optional. Limits: 100 hosts, 500 unique directed connections, 30 applications/services per host, 120-character metadata, 40-character IDs and ports 1–65535. Unknown fields, duplicate IDs, invalid edges, YAML aliases/object tags and excessive nesting are rejected.

Choose an initial computer and OS assumption. NetworkX follows only supplied connections; isolated or OS-excluded computers are not traversed. Direct exposure is one edge away; secondary exposure is farther away. PyVis renders an offline interactive graph; Plotly provides a fallback.

Reachable-asset priority is clamped to 0–100:

`20 + 12 × criticality + min(20, 5 × services) − 15 for endpoint protection − 10 for least privilege`

Unreachable assets score zero; scores of at least 70 are High priority. This ranks review priorities, not compromise probabilities. Isolation what-if controls compare exposed counts. Recommendations follow supplied services, controls and inventory. The conceptual kill chain describes assumptions; no execution, vulnerability match or actual compromise is inferred.

## Storage and privacy

**Local mode** uses disk-backed SQLite at `.runtime/scans.db`, with WAL, transactions, bounded queries and a busy timeout. Each browser session receives a random private scope; new sessions start a new workspace. Existing data is preserved when upgrading the application.

**Production mode** requires PostgreSQL with certificate verification and Streamlit OpenID Connect sign-in. History belongs to a hash of the verified issuer/subject identifiers and follows the same account across sessions. An optional subject allowlist restricts access. Production mode refuses to start with missing authentication or a SQLite fallback.

One record is saved per owner/file hash/model version. Experiment records remain separate from scan counts. SQL parameters, scoped reads/deletes, pooled connections, connection/query timeouts and a versioned schema protect database operations. Future incompatible schema versions fail explicitly instead of silently modifying records.

No raw binary, plaintext, password or key is persisted. Filename retention can be disabled. Retention defaults to 30 days and runs on application activity; schedule a separate operational cleanup if expiry must occur while the app is stopped. History has 50-row pages; exports contain the indicated page, and scenario exports contain the latest 100 records. UTC is used throughout. Database backups/WAL copies need their own retention policy.

## Configuration and hosting readiness

`requirements.txt` is the authoritative dependency definition. Entry point: `streamlit_app.py`. Choose Python 3.15 on the host and include `malguard/`, `model/`, `lottiefiles/`, `.streamlit/config.toml` and the requirements file. Training datasets are only needed for retraining. Do not upload `.venv`, `.runtime`, caches or secrets to GitHub.

For [Streamlit Community Cloud](https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/deploy), set the entry point and Python version in Advanced settings. Add production configuration through the host's Secrets settings. For a local preflight, place it in ignored `.streamlit/secrets.toml`:

```toml
MALGUARD_MODE = "production"
MALGUARD_DATABASE_URL = "postgresql+psycopg://USER:URL_ENCODED_PASSWORD@HOST:5432/DATABASE?sslmode=verify-full&sslrootcert=system"
MALGUARD_RETENTION_DAYS = 30
# Optional: identity-provider subject IDs permitted to use the app.
# Without a list, every account accepted by your configured provider is allowed.
MALGUARD_ALLOWED_SUBJECTS = ["PROVIDER_SUBJECT_ID"]

[auth]
redirect_uri = "https://YOUR-APP.streamlit.app/oauth2callback"
cookie_secret = "REPLACE_WITH_A_LONG_RANDOM_SECRET"
client_id = "YOUR_OIDC_CLIENT_ID"
client_secret = "YOUR_OIDC_CLIENT_SECRET"
server_metadata_url = "https://YOUR-PROVIDER/.well-known/openid-configuration"
```

Create the identity-provider client with the exact callback URL and configure an existing PostgreSQL database. Use your provider's trusted CA file if system trust is insufficient. Never disable certificate verification. Use a dedicated database role with access only to this application's schema; initial startup needs table/index creation rights. Keep credentials outside Git. The app's built-in authentication follows [Streamlit's OIDC configuration](https://docs.streamlit.io/develop/concepts/connections/authentication).

| Setting | Default | Purpose |
|---|---|---|
| `MALGUARD_MODE` | `local` | `production` enforces PostgreSQL and sign-in |
| `MALGUARD_DATABASE_URL` | local SQLite file | PostgreSQL/SQLite connection URL; environment overrides root Streamlit secrets |
| `MALGUARD_RETENTION_DAYS` | `30` | Retention from 1–3650 days |
| `MALGUARD_ALLOWED_SUBJECTS` | empty | Production account allowlist; list in secrets or comma-separated environment value |
| `MALGUARD_MAX_UPLOAD_MB` | `20` | Environment variable, clamped to 1–50 MiB |

Run `./scripts/project.ps1 -PythonArgs @('scripts/check_hosting.py')` for local readiness, or add `'--production'` to check deployment settings and PostgreSQL connectivity without creating resources. Complete a real sign-in and account-isolation check against your provider, plus backup/restore validation, before release. No hosted database or identity provider is bundled or provisioned.

On a self-managed host, override `server.address` to `0.0.0.0` behind your HTTPS reverse proxy and set its required port; the committed localhost default is for local safety. Community Cloud manages its own proxy/server overrides. Keep XSRF/CORS enabled. Ephemeral host disks are not suitable for durable SQLite history.

This repository has not been deployed. Production operation also needs HTTPS, resource/concurrency limits, monitoring, patching, and tested backups. Static parsing has input/time limits but is not a hardened operating-system malware sandbox. Classification can miss malware or flag legitimate software; simulation outcomes are hypotheses.

## Project structure

```text
streamlit_app.py          Streamlit entry point
start.ps1                Isolated Windows launcher
main.py, file_checker.py CLI-compatible file analysis
model_trainer.py         Reproducible model training
malguard/                Analysis, crypto, storage, settings, UI and simulations
malguard/assets/         Vendored offline Lottie player and its MIT license
lottiefiles/             Original animation assets
model/                   Packaged model, manifest and original artifacts
datasets/                Training data and original notebook
scripts/                 Environment, dependency and hosting checks
tests/                   Regression, integration and security coverage
.streamlit/config.toml   Theme and server configuration
```

For development checks, run `./scripts/project.ps1 -PythonArgs @('-m','pytest','-q')`. Changes to dependencies, feature extraction, model artifacts or storage must preserve the scan/encryption workflows and account isolation. The Lottie player is pinned to 5.13.0 with its license retained in `malguard/assets/lottie.LICENSE`.
