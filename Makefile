.PHONY: help build test docs docs-build clean

PYTHON  := python3

# ── help ──────────────────────────────────────────────────────────────────────

help:
	@echo ""
	@echo "  make build                    Build sdist and wheel into dist/"
	@echo "  make test                     Run tests with coverage"
	@echo "  make docs                     Serve docs locally (hot-reload)"
	@echo "  make docs-build               Build static docs into site/"
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

# ── clean ─────────────────────────────────────────────────────────────────────

clean:
	rm -rf dist/ build/ site/ *.egg-info .coverage htmlcov/ coverage.xml
