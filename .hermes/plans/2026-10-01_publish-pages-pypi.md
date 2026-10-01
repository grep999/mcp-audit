# Publish Plan: GitHub Pages + PyPI

> For Hermes: execute task-by-task, verify each external side effect, apply publish gates.

**Goal:** Make `mcp-audit` reachable two ways — a live landing (GitHub Pages) and installable via `pip install mcp-audit` (PyPI). Landing is deployable now; PyPI is blocked on an account token.

**Architecture:**
- **GitHub Pages** — static deploy branch is now obsolete. Use a GitHub Actions workflow with `actions/deploy-pages` + `actions/upload-pages-artifact` (Pages must be enabled server-side first via API; needs `pages` scope on the token).
- **PyPI** — publish `dist/` wheel + sdist with `twine`, prefer the trusted-publisher GitHub Action (`pypa/gh-action-pypi-publish`) for all future releases; manual `twine` only for the first manual upload.

**Tech Stack:** GitHub Actions + `actions/configure-pages` | Python `setuptools` + `build` + `twine`.

---

## Part A — GitHub Pages

### A1. Enable Pages via API
```bash
gh api repos/grep999/mcp-audit/pages -X POST \
  -f 'source[branch]=gh-pages' -f 'source[path]=/' \
  -H 'Accept: application/vnd.github+json'
```
**Gate:** requires `pages` token scope (current: `gist, read:org, repo, workflow` — MISSING). If token lacks `pages`, use a PAT with `repo` + `admin:repo_hook` + `workflow`, or enable it in the repo Settings → Pages UI.

### A2. Add publish workflow
Create `.github/workflows/pages.yml`:
```yaml
name: Deploy Pages
on:
  push:
    branches: [main]
  workflow_dispatch:
permissions:
  contents: read
  pages: write
  id-token: write
concurrency:
  group: pages
  cancel-in-progress: true
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/configure-pages@v5
      - uses: actions/upload-pages-artifact@v3
        with: { path: landing }
  deploy:
    needs: build
    runs-on: ubuntu-latest
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    steps:
      - id: deployment
        uses: actions/deploy-pages@v4
```

### A3. Verify
- `gh api repos/grep999/mcp-audit/pages` → `html_url` = `https://grep999.github.io/mcp-audit/`.
- Fetch the URL → HTTP 200 + HTML title matches.

**Risk:** Pages serves `mcp-audit.dev` only if CNAME is set (needs domain). Default URL is `grep999.github.io/mcp-audit`. `og:image`/`canonical` point at `https://mcp-audit.dev/` — update `canonical` to the real Pages URL until a custom domain is added, or add CNAME record.

---

## Part B — PyPI

### B1. prepack
```bash
python3 -m build   # or uv build -> dist/
```
Verify sdist + wheel exist in `dist/`.

### B2. Publish (two options)
- **Trusted publisher (recommended, token-free):** add workflow `publish.yml` using `pypa/gh-action-pypi-publish`, configure PyPI trusted-publisher for this repo.
- **Manual token:** install `twine` (`pip install twine`), set `PYPI_TOKEN` env, run:
```bash
python3 -m twine upload dist/*
```
**Gate:** `PYPI_TOKEN` is NOT set (checked). Manual publish needs the token — required from user, or go the trusted-publisher route.

### B3. Verify + smoke
- `pip install mcp-audit` in a fresh venv → `mcp-audit --version`.
- `pip download mcp-audit` sanity.
- Check `https://pypi.org/pypi/mcp-audit/json` → HTTP 200, version 0.1.0.

---

## Files likely to change
- Create: `.github/workflows/pages.yml`
- Create: `.github/workflows/publish.yml` (PyPI, if trusted-publisher)
- Modify: `landing/index.html` (canonical + og:url to real Pages URL)
- Create: `dist/` (build artifact, gitignored)
- Modify: `.gitignore` (`dist/`, `build/`)

## Tests / validation
- Pages: HTTP 200 on the URL, title/link check.
- PyPI: `pip install mcp-audit` in clean venv.

## Open questions (need user)
1. **Token scopes:** my `gh` token lacks `pages` — enable Pages via a PAT/admin or Settings UI? Provide the token/PAT or point me to add the scope.
2. **PyPI auth:** no `PYPI_TOKEN` set. Manual `twine` token, or trusted-publisher Actions workflow (I'll add a publish job)?
3. **Landing canonical:** `mcp-audit.dev` is aspirational until DNS is bought. Point `canonical` at `grep999.github.io/mcp-audit/` meanwhile, or buy the domain first?

## Fastest path (0 prerequisites)
Even before the blockers resolve, I can:
- Add the Pages workflow file (deployable the moment Pages is enabled).
- Add the PyPI trusted-publisher workflow (token-free once PyPI publisher is linked).
- Build `dist/` locally and verify it.

Proceed with those, and the two external publishes (Pages enable + PyPI upload) trip the user gate.