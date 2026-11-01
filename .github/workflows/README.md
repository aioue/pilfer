# GitHub Actions Workflows

This directory contains automated workflows for the pilfer project.

## Workflows

### `ci.yml` - Quick CI

Fast, essential testing on every push and pull request.

- Python 3.12 on Ubuntu
- Ruff lint (`requirements-dev.txt` pin)
- Unified test suite
- Standalone `pilfer.py --version` check

### `test.yml` - Comprehensive Test Suite

Thorough validation for larger changes and pre-release checks.

- Multi-Python matrix (3.10–3.13)
- Ruff lint (`requirements-dev.txt` pin)
- Bandit (`-ll`, fails on medium+; SARIF uploaded to Security)
- Coverage reports uploaded as artifacts

### `codeql.yml` - Code scanning

CodeQL for Python and Actions, as a repo workflow (advanced setup). GitHub's
default setup ignores config files, so it scanned `tests/` and raised an alert
for every fixture that writes a fake password. Default setup must stay off in
Settings > Code security; GitHub refuses advanced-setup results while it is on.

- Runs on push and pull request to main/master, and weekly
- Results appear in the repository Security tab
- Config: [`.github/codeql/codeql-config.yml`](../codeql/codeql-config.yml) (`paths-ignore: tests`)
- [`dismiss-codeql-fp.yml`](dismiss-codeql-fp.yml) dismisses the vault session-binding SHA-256 false positive after each CodeQL run
- Complements Bandit (Python-specific rules) in `test.yml`

### `auto-merge.yml` - Dependabot and CodeQL action bumps

Enables auto-merge on Dependabot pull requests for minor and patch updates after required checks pass. Major version bumps stay for review. A pip release note that says "breaking change" also stays for review. The same phrase on a GitHub Action pin does not, including `codeql-action`: the pin is the whole diff, and a pin that breaks CI never satisfies the required checks.

### `release.yml` - Release and PyPI publish

Runs on version tags (`v*`) and can be dry-run with `workflow_dispatch`.

1. Validates `pyproject.toml`, `pilfer/__init__.py`, and `pilfer.py` versions match the tag
2. Runs the test suite
3. Builds sdist and wheel (`python -m build`, `twine check`)
4. Creates a GitHub release with distribution artifacts
5. Publishes to PyPI using trusted publishing (OIDC)

Tag pushes publish. Manual `workflow_dispatch` validates and builds only.

## Dependabot

`.github/dependabot.yml` opens weekly PRs (Mondays 09:00 UTC) for:

- GitHub Actions updates (one grouped PR)
- Python dependencies from `pyproject.toml` and `requirements-dev.txt` (minor/patch grouped separately from major)
- Labels: `dependencies`, plus `github-actions` or `python`
- Cooldown on pip updates (longer wait for major semver bumps)
- Security updates remain immediate and are not batched with version updates

## Triggers

| Workflow | Push/PR | Tags | Manual |
|----------|---------|------|--------|
| `ci.yml` | main, master | - | - |
| `test.yml` | main, master | - | yes |
| `auto-merge.yml` | Dependabot PRs | - | - |
| `codeql.yml` | main, master (+ weekly) | - | - |
| `release.yml` | - | `v*` | yes (dry-run) |

## Releasing

1. Bump the version in all three places:
   - `pyproject.toml`
   - `pilfer/__init__.py`
   - `pilfer.py`
2. Commit and push to `master`
3. Tag and push:

```bash
git commit -am "chore(release): X.Y.Z"
git push origin master
git tag vX.Y.Z
git push origin vX.Y.Z
```

4. The Release workflow creates the GitHub release and publishes to PyPI

### PyPI trusted publishing (one-time setup)

Configure on [pypi.org](https://pypi.org/manage/project/pilfer/settings/publishing/):

| Field | Value |
|-------|-------|
| PyPI project name | `pilfer` |
| Owner | `aioue` |
| Repository | `pilfer` |
| Workflow name | `release.yml` |
| Environment name | *(leave blank)* |

The `pypi-publish` job omits a GitHub environment so OIDC claims match PyPI.
A follow-up `record-pypi-deployment` job uses the `pypi` environment only to
record a successful deployment on GitHub after publish completes.

Trusted publishing uses OIDC (`id-token: write`) - no long-lived PyPI API token in secrets.

### Local publish (fallback)

`build_and_publish.sh` remains for manual TestPyPI or PyPI uploads when needed.

## Best Practices

### Security

- Minimal `permissions` on each workflow
- PyPI trusted publishing instead of stored API tokens
- Dependabot alerts, security updates, and grouped security PRs
- CodeQL code scanning (GitHub default setup)
- Bandit in CI with SARIF upload (`test.yml`); config in `pyproject.toml`

### Performance

- Pip dependency caching
- Parallel jobs in the test suite
- Concurrency groups cancel superseded runs

### Reliability

- Version consistency checks before release
- `twine check` on built artifacts
- Matrix testing across Python versions
- Release artifacts preserved on GitHub

## Local Development

```bash
git clone https://github.com/aioue/pilfer.git
cd pilfer
pip install -e .
pilfer --help

# Quick test (same as ci.yml)
cd tests && python run_tests.py
```

```bash
# Lint (same pin as ci.yml / test.yml)
pip install -r requirements-dev.txt
ruff check pilfer/ pilfer.py tests/

# Security scanning
pip install "bandit[toml,sarif]"
bandit -r pilfer/ pilfer.py -c pyproject.toml -ll

# Release dry-run (build only)
python -m pip install build twine
python -m build
python -m twine check dist/*
```

Use [conventional commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`) so release notes stay readable. Optional: `./scripts/release-notes.sh` before tagging.

Manual publish when trusted publishing is unavailable:

```bash
pip install build twine
chmod +x build_and_publish.sh
./build_and_publish.sh test   # TestPyPI
./build_and_publish.sh prod   # production PyPI
```
