.PHONY: help build test docs docs-build release clean

PYTHON  := python3
# Read current version from pyproject.toml (no external deps)
CURRENT_VERSION := $(shell grep '^version' pyproject.toml | sed 's/version = "\(.*\)"/\1/')

# ── help ──────────────────────────────────────────────────────────────────────

help:
	@echo ""
	@echo "  pipguard $(CURRENT_VERSION)"
	@echo ""
	@echo "  make build                    Build sdist and wheel into dist/"
	@echo "  make test                     Run tests with coverage"
	@echo "  make docs                     Serve docs locally (hot-reload)"
	@echo "  make docs-build               Build static docs into site/"
	@echo "  make release NEW_VERSION=x.y.z  Bump version, commit, tag, GitHub Release"
	@echo "  make clean                    Remove build artifacts"
	@echo ""

# ── build ─────────────────────────────────────────────────────────────────────

build:
	$(PYTHON) -m build

# ── test ──────────────────────────────────────────────────────────────────────

test:
	pytest --cov=pipguard --cov-report=term-missing

# ── docs ──────────────────────────────────────────────────────────────────────

docs:
	mkdocs serve

docs-build:
	mkdocs build --strict

# ── release ───────────────────────────────────────────────────────────────────
#
# Usage:  make release NEW_VERSION=0.2.0
#
# What it does (all local — no external services during this step):
#   1. Validates NEW_VERSION is provided and tests pass
#   2. Updates version in pyproject.toml
#   3. Stages pyproject.toml + CHANGELOG.md and commits
#   4. Creates an annotated git tag vNEW_VERSION
#   5. Pushes commit + tag → triggers CI publish to PyPI
#   6. Creates a GitHub Release with notes extracted from CHANGELOG.md

release:
ifndef NEW_VERSION
	$(error Usage: make release NEW_VERSION=0.2.0)
endif
	@echo "→ Checking working tree is clean..."
	@git diff --exit-code --quiet || (echo "ERROR: Uncommitted changes. Commit or stash first." && exit 1)
	@git diff --cached --exit-code --quiet || (echo "ERROR: Staged changes. Commit or stash first." && exit 1)

	@echo "→ Running tests before release..."
	@pytest -q --tb=short || (echo "ERROR: Tests failed. Fix before releasing." && exit 1)

	@echo "→ Checking CHANGELOG.md has an entry for $(NEW_VERSION)..."
	@grep -q "^\#\# \[$(NEW_VERSION)\]" CHANGELOG.md || \
		(echo "ERROR: No '## [$(NEW_VERSION)]' entry found in CHANGELOG.md. Add release notes first." && exit 1)

	@echo "→ Bumping version $(CURRENT_VERSION) → $(NEW_VERSION)"
	@sed -i '' 's/^version = "$(CURRENT_VERSION)"/version = "$(NEW_VERSION)"/' pyproject.toml

	@git add pyproject.toml CHANGELOG.md
	@git commit -m "chore: release v$(NEW_VERSION)"

	@echo "→ Creating annotated tag v$(NEW_VERSION)..."
	@git tag -a "v$(NEW_VERSION)" -m "v$(NEW_VERSION)"

	@echo "→ Pushing commit and tag..."
	@git push origin main
	@git push origin "v$(NEW_VERSION)"

	@echo "→ Creating GitHub Release..."
	@awk '/^\#\# \[$(NEW_VERSION)\]/{found=1; next} /^\#\# \[/{if(found) exit} found && NF{print}' \
		CHANGELOG.md | \
		gh release create "v$(NEW_VERSION)" \
			--title "v$(NEW_VERSION)" \
			--notes-file -

	@echo ""
	@echo "✓ Released v$(NEW_VERSION)"
	@echo "  PyPI publish: https://github.com/shenxianpeng/pipguard/actions"
	@echo "  Release:      https://github.com/shenxianpeng/pipguard/releases/tag/v$(NEW_VERSION)"

# ── clean ─────────────────────────────────────────────────────────────────────

clean:
	rm -rf dist/ build/ site/ *.egg-info .coverage htmlcov/ coverage.xml
