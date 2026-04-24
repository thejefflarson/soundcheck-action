# Soundcheck Security Review (v2)

Runs a [Soundcheck](https://github.com/thejefflarson/soundcheck) security
review against your repository on every pull request. Comments a
severity-ranked findings table on the PR and, when autofix is enabled,
commits rewrites back to the PR branch.

Backed by Soundcheck's 45 skills covering OWASP Web Top 10:2025, OWASP
LLM Top 10:2025, and API Security Top 10:2023.

## Usage

```yaml
name: Security Review
on:
  pull_request:
    branches: ["**"]

jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      contents: write        # only needed if autofix is enabled
      pull-requests: write
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0     # full history so --diff-base can resolve

      - uses: thejefflarson/soundcheck-action@v2
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

## What it does

On a `pull_request` event:

1. Clones Soundcheck at a pinned commit SHA (supply-chain-safe) and
   installs the `claude` CLI on the runner.
2. Runs the review script scoped to the files changed in the PR
   (`--diff-base origin/<base-branch>`), with the pinned skill file as
   the reviewer's system prompt.
3. If `autofix: true` (the default), the reviewer gets Edit access and
   rewrites Critical/High/Medium findings in place; the runner then
   commits the rewrites back to the PR branch.
4. Comments the findings table on the PR and writes the same summary
   to the job step summary.

On `workflow_dispatch` or `schedule` (no PR context):

1. Same setup, but runs a full-repo scan (no `--diff-base`).
2. If autofix rewrites any files, pushes them to a
   `soundcheck/security-review` branch and opens (or updates) a PR
   against the base branch.
3. Writes the summary to the job step summary.

The CLI exits non-zero (1) on any Critical/High finding, which the
action surfaces via `outputs.exit-code`. Wire that into a required
check if you want the review to gate merges.

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `anthropic-api-key` | Yes | — | Anthropic API key (repo secret) |
| `github-token` | Yes | — | Token with `pull-requests:write` (+ `contents:write` if autofix) |
| `base-branch` | No | repo default | Branch to diff against on PRs and open PRs into on scheduled runs |
| `model` | No | `sonnet` | Whatever `claude -p --model` accepts — a short alias (`sonnet`, `haiku`) or a full model id |
| `autofix` | No | `true` | Grant the reviewer Edit access and commit rewrites back |
| `max-budget-usd` | No | `5` | Aggregate spend cap across review + autofix |
| `timeout-seconds` | No | `900` | Subprocess timeout passed to the reviewer CLI |

## Outputs

| Output | Description |
|---|---|
| `pr-url` | PR URL if one was opened/updated. Empty on diff-only runs. |
| `findings-count` | Total findings returned by the reviewer |
| `exit-code` | Reviewer exit code — `0` clean, `1` Critical/High findings, `2` infrastructure error |

## Non-Anthropic providers (Bedrock, Vertex)

The reviewer shells out to `claude -p --model <X>`, so whatever model
string the `claude` CLI accepts, this action accepts. For Bedrock or
Vertex, set the provider-selection env vars on the job and pass the
ARN/model id via `model`:

```yaml
jobs:
  review:
    runs-on: ubuntu-latest
    env:
      CLAUDE_CODE_USE_BEDROCK: "1"
      AWS_REGION: us-east-1
      # plus AWS credentials — SSO, IAM role, or access keys
    permissions:
      contents: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0
      - uses: thejefflarson/soundcheck-action@v2
        with:
          anthropic-api-key: ""    # unused on Bedrock, still required by the input schema
          github-token: ${{ secrets.GITHUB_TOKEN }}
          model: arn:aws:bedrock:us-east-1:...:application-inference-profile/...
```

The reviewer runs a preflight ping before the real review, so a
misconfigured provider fails in seconds with a pointer to the env vars
rather than after the full timeout with no output.

## Secrets

Add your Anthropic API key as a repository secret:
**Settings → Secrets and variables → Actions → New repository secret**
named `ANTHROPIC_API_KEY`.

## Migrating from v1

- **`max-files` is gone.** PR runs now use `--diff-base` to scope the
  review to changed files; scheduled runs scan the whole repo.
  `max-files` had no direct replacement and is no longer honored.
- **Autofix is now an explicit `autofix: true` input.** Same default
  behavior as v1 (commits rewrites back), just now a visible toggle
  you can flip off for comment-only PR gating.
- **Default model alias.** `model` defaults to `sonnet` instead of
  `claude-sonnet-4-6`. Both still work; the alias tracks the newest
  release without an action bump.
- **Python SDK dependency removed.** v1 `pip install anthropic`'d its
  own script; v2 runs Soundcheck's pinned CLI via `claude -p`.

## License

MIT
