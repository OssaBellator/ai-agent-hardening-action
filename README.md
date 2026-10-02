# AI Agent Repository Hardening Scan

A dependency-free GitHub Action for static, evidence-only review of AI-assisted repositories.

It inventories common agent instruction files, MCP configuration, GitHub Actions workflows, and dependency manifests, and flags a small set of high-signal credential-pattern and authority risks. It does **not** execute target repository code, install target dependencies, read environment credentials, or print suspected secret values.

## Use

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@v4
  - id: hardening
    uses: OssaBellator/ai-agent-hardening-action@v1
```

By default the Action is advisory-only. To fail CI on high-severity findings:

```yaml
- uses: OssaBellator/ai-agent-hardening-action@v1
  with:
    fail-on: high
```

Accepted thresholds: `never` (default), `high`, `medium`, and `any`.

## SARIF / GitHub Code Scanning

The Action writes `agent-hardening-scan.sarif` and exposes the path as the `sarif-file` output. The scanner itself requires only `contents: read`.

To upload findings to GitHub Code Scanning, opt in from the caller workflow:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - id: hardening
    uses: OssaBellator/ai-agent-hardening-action@v1
  - uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: ${{ steps.hardening.outputs.sarif-file }}
```

## Evidence boundary

Pattern matches are review signals, not proof of exploitability or compromise. The scanner does not inspect private account settings, runtime traffic, developer machines, or external secret stores.

For a human-reviewed public-repository audit, see https://ossabellator.github.io/ai-agent-hardening/audit.html

## License

MIT.
