# GitHub Actions Workflows

This directory contains automated workflows for the pilfer project.

## Workflows

### `ci.yml` - Quick CI

Fast, essential testing on every push and pull request.

- Python 3.12 on Ubuntu
- Ruff lint
- Unified test suite
- Standalone `pilfer.py --version` check

### `test.yml` - Comprehensive Test Suite

Thorough validation for larger changes and pre-release checks.

- Multi-Python matrix (3.10–3.13)
- Ruff lint
- Bandit (`-ll`, fails on medium+; SARIF uploaded to Security)
- Coverage reports uploaded as artifacts

### `codeql.yml` - Code scanning

GitHub CodeQL static analysis for Python.

- Runs on push, pull request, and weekly schedule
- Results appear in the repository Security tab
- Complements Bandit (Python-specific rules) in `test.yml`

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
- Python dependencies from `pyproject.toml` (minor/patch grouped separately from major)
- Labels: `dependencies`, plus `github-actions` or `python`
- Cooldown on pip updates (longer wait for major semver bumps)
- Security updates remain immediate and are not batched with version updates

## Triggers

| Workflow | Push/PR | Tags | Manual |
|----------|---------|------|--------|
| `ci.yml` | main, master | - | - |
| `test.yml` | main, master | - | yes |
| `codeql.yml` | main, master | - | - |
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
- CodeQL code scanning (`codeql.yml`)
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
# Quick test (same as ci.yml)
cd tests && python run_tests.py

# Lint (same as ci.yml / test.yml)
ruff check pilfer/ pilfer.py tests/

# Security scanning
pip install "bandit[toml]"
bandit -r pilfer/ pilfer.py -c pyproject.toml -ll

# Release dry-run
python -m pip install build twine
python -m build
python -m twine check dist/*
```
