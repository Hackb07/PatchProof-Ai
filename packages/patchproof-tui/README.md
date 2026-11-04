# PatchProof TUI

After the package is published to npm, install it globally:

```sh
npm install --global patchproof-tui
patchproof-tui
```

Requires Node.js 18+ and a running PatchProof API (`cargo run -p patchproof-api` from the project checkout). Configure the endpoint and API key as needed:

```sh
PATCHPROOF_API=http://127.0.0.1:8000 PATCHPROOF_API_KEY=your-key patchproof-tui
```

In PowerShell:

```powershell
$env:PATCHPROOF_API = 'http://127.0.0.1:8000'
$env:PATCHPROOF_API_KEY = 'your-key'
patchproof-tui
```

The terminal app starts scans, polls progress, prints findings and verification results, saves Markdown security reports, and exports generated fixes as patch bundles. Patch bundles are proposals; review them before applying. The PatchProof pipeline also applies and verifies fixes in its scan checkout.

To publish a release, authenticate with the npm account that owns the package name and run `npm publish` from this directory. Consumers can install it once published.
