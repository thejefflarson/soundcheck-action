# Soundcheck Security Review

Automated OWASP security review for your repository. Scans your source code, rewrites
Critical, High, and Medium findings in place, and opens a pull request with the changes
and a severity-ranked findings table.

Powered by [Soundcheck](https://github.com/thejefflarson/soundcheck) — 29 skills covering
OWASP Web Top 10:2025 and OWASP LLM Top 10:2025.

## Usage

```yaml
name: Security Review
on:
  workflow_dispatch:
  schedule:
    - cron: "0 9 * * 1"  # every Monday

jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4

      - uses: thejefflarson/soundcheck-action@main
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

## What it does

1. Globs all source files (`*.py`, `*.js`, `*.ts`, `*.go`, `*.java`, `*.rb`, `*.php`, `*.cs`, `*.rs`)
2. Sends them to Claude with the full Soundcheck skill suite as context
3. Rewrites every Critical, High, and Medium finding in place
4. Commits the rewrites to a `soundcheck/security-review` branch
5. Opens a PR (or updates the existing one) with a severity-ranked findings table

If no rewriteable findings exist, no PR is opened.

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `anthropic-api-key` | Yes | — | Anthropic API key |
| `github-token` | Yes | — | Token with `contents:write` and `pull-requests:write` |
| `base-branch` | No | repo default | Branch to open the PR against |
| `max-files` | No | `50` | Max source files to include (increase for large repos) |
| `model` | No | `claude-sonnet-4-6` | Claude model to use |

## Outputs

| Output | Description |
|---|---|
| `pr-url` | URL of the opened or updated PR (empty if no findings) |
| `findings-count` | Total findings across all severities |

## Secrets

Add your Anthropic API key as a repository secret named `ANTHROPIC_API_KEY`:
**Settings → Secrets and variables → Actions → New repository secret**

## License

MIT
