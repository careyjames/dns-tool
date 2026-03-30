# Single-Repo Migration — GitHub Instructions

**Date:** 2026-03-30
**Migration:** `dns-tool-intel` (private) + `dns-tool-web` (public) → `dns-tool` (public, BUSL-1.1)

All codebase changes are complete. This document covers the GitHub-side actions you need to perform.

---

## Step 1: Rename dns-tool-intel → dns-tool

1. Go to **github.com/IT-Help-San-Diego/dns-tool-intel** → Settings → General
2. Under "Repository name", change `dns-tool-intel` to `dns-tool`
3. Click "Rename"
4. GitHub automatically creates a redirect from the old URL

> This preserves all commit history, stars, issues, and Actions. The old `dns-tool-intel` URL will redirect.

---

## Step 2: Change Visibility to Public

1. Go to **github.com/IT-Help-San-Diego/dns-tool** → Settings → General
2. Scroll to "Danger Zone" → "Change repository visibility"
3. Change from **Private** to **Public**
4. Confirm by typing the repository name

> BUSL-1.1 license protects the IP. The latest shipping version is always commercially protected; each version converts to Apache 2.0 three years after release.

---

## Step 3: Archive dns-tool-web

1. Go to **github.com/IT-Help-San-Diego/dns-tool-web** → Settings → General
2. Scroll to "Danger Zone" → "Archive this repository"
3. Click "Archive this repository"

> This makes dns-tool-web read-only. Existing links still work. The repo description should note "Archived — consolidated into IT-Help-San-Diego/dns-tool".

---

## Step 4: Push the Updated Codebase

From the Replit workspace, run:

```bash
bash scripts/git-sync.sh
```

This pushes all the migration changes (updated references, rewritten release.sh, deprecated mirror scripts) to the now-public `dns-tool` repo.

---

## Step 5: SonarCloud Cleanup

1. Go to **sonarcloud.io** → Organization: `ithelpsandiego`
2. Delete or archive these redundant projects:
   - `dns-tool-web` (the public mirror project — no longer needed)
   - `careyjames_dns-tool` (auto-imported duplicate)
   - `careyjames_dns-tool-intel` (auto-imported duplicate)
3. Keep `dns-tool-full` as the single canonical project
4. Update the `dns-tool-full` project settings:
   - Repository: `IT-Help-San-Diego/dns-tool` (should auto-update after rename)
   - Project display name: "DNS Tool"

---

## Step 6: Update Zenodo

1. Go to **zenodo.org** → Your uploads → DNS Tool record
2. Update the "Related identifiers" URL from `dns-tool-web` to `dns-tool`
3. The DOI (10.5281/zenodo.18854899) remains valid — it points to the Zenodo record, not the GitHub URL directly
4. Future releases via `scripts/release.sh` will create tags on `dns-tool` (Zenodo webhook may need re-linking)

---

## Step 7: Verify

After completing all steps:

- [ ] `github.com/IT-Help-San-Diego/dns-tool` is public and has all code
- [ ] `github.com/IT-Help-San-Diego/dns-tool-web` is archived
- [ ] `github.com/IT-Help-San-Diego/dns-tool-intel` redirects to `dns-tool`
- [ ] SonarCloud shows only `dns-tool-full` project
- [ ] GitHub Actions CI runs on the renamed repo
- [ ] Security advisories link to `dns-tool` (not `dns-tool-web`)
- [ ] `dnstool.it-help.tech` still serves correctly (deployment is independent of repo name)

---

## What Changed in the Codebase

All these changes are already committed and ready to push:

1. **Metadata files** (README, LICENSE refs, CITATION.cff, codemeta.json, NOTICE, CONTRIBUTING.md, BUILD.md, LICENSING.md) — all point to `dns-tool`
2. **SonarCloud config** — single project key `dns-tool-full`, name "DNS Tool"
3. **Go source** — all `_oss.go` stubs reference build tags instead of repo names; boundary tests verify build-tag gating instead of asserting file absence
4. **Templates** — footer, privacy, architecture, security pages all link to `dns-tool`
5. **Documentation** — all docs updated; architecture diagrams reference single-repo model
6. **Release pipeline** — `release.sh` rewritten for single-repo (no more two-repo push/filter logic)
7. **Mirror artifacts deprecated** — `sync-to-web.sh`, `fix-sonar-web.py`, `public-excludes.txt` contain deprecation notices
8. **GitHub config** — issue templates, security redirect workflow, `.zenodo.json` all reference `dns-tool`
9. **Scripts** — `git-sync.sh`, `git-push.sh`, `git-health-check.sh` all target `dns-tool`

---

## Rollback Plan

If something goes wrong:

1. Rename `dns-tool` back to `dns-tool-intel` in GitHub Settings
2. Change visibility back to Private
3. Un-archive `dns-tool-web`
4. The mirror workflow files are deprecated but the scripts still exist — they would need to be restored from git history if needed
