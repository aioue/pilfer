# GitHub Actions Workflows

This directory contains automated workflows for the pilfer project.

## Workflows

### `ci.yml` - Quick CI

Fast, essential testing on every push and pull request.

- Python 3.12 on Ubuntu
- Unified test suite
- Standalone `pilfer.py --version` check

### `test.yml` - Comprehensive Test Suite

Thorough validation for larger changes and pre-release checks.

- Multi-Python matrix (3.8-3.12)
- Black, isort, and flake8
- Bandit and safety scans
- Coverage reports uploaded as artifacts

### `release.yml` - Release and PyPI publish

Runs on version tags (`v*`) and can be dry-run with `workflow_dispatch`.

1. Validates `pyproject.toml`, `pilfer/__init__.py`, and `pilfer.py` versions match the tag
2. Runs the test suite
3. Builds sdist and wheel (`python -m build`, `twine check`)
4. Creates a GitHub release with distribution artifacts
5. Publishes to PyPI using trusted publishing (OIDC)

Tag pushes publish. Manual `workflow_dispatch` validates and builds only.

## Dependabot

`.github/dependabot.yml` opens weekly PRs for:

- GitHub Actions updates (grouped)
- Python dependencies from `pyproject.toml` (grouped)

## Triggers

| Workflow | Push/PR | Tags | Manual |
|----------|---------|------|--------|
| `ci.yml` | main, master | - | - |
| `test.yml` | main, master | - | yes |
| `release.yml` | - | `v*` | yes (dry-run) |

## Releasing

1. Bump the version in all three places:
   - `pyproject.toml`
   - `pilfer/__init__.py`
   - `pilfer.py`
2. Commit and push to `master`
3. Tag and push:

```bash
git tag v2.21.0
git push origin v2.21.0
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
| Environment name | `pypi` |

Then create a GitHub environment named `pypi` under **Settings → Environments**. Optional: add required reviewers for manual approval before publish.

Trusted publishing uses OIDC (`id-token: write`) - no long-lived PyPI API token in secrets.

### Local publish (fallback)

`build_and_publish.sh` remains for manual TestPyPI or PyPI uploads when needed.

## Best Practices

### Security

- Minimal `permissions` on each workflow
- PyPI trusted publishing instead of stored API tokens
- Dependency scanning with safety
- Code security analysis with bandit

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

# Code formatting
black --check pilfer/ pilfer.py tests/
isort --check-only pilfer/ pilfer.py tests/
flake8 pilfer/ pilfer.py tests/ --max-line-length=100

# Security scanning
bandit -r pilfer/ pilfer.py
safety check

# Release dry-run
python -m pip install build twine
python -m build
python -m twine check dist/*
```
