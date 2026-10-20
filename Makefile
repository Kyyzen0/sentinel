# SENTINEL — Makefile
# P4-A follow-up : commandes courantes pour les contributeurs.
# Usage : `make <target>` (ou `make help` pour la liste).

.PHONY: help install dev gui test test-all test-gui lint format typecheck check coverage clean run-scan run-baseline pre-commit-install pre-commit-run

PYTHON ?= python3
PIP    ?= $(PYTHON) -m pip

help:           ## affiche cette aide
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

install:        ## pip install -e . (prod-only, pas de dev-deps)
	$(PIP) install -e .

dev:            ## pip install -e .[dev] (ruff, hypothesis, coverage, mypy, pre-commit)
	$(PIP) install -e ".[dev]"

gui:            ## pip install -e .[gui] (PySide6, lanceur sentinel-gui)
	$(PIP) install -e ".[gui]"

test:           ## tests unitaires (sans les property-based, ~5s)
	$(PYTHON) -m unittest discover -s tests -k 'not property_based' -v

test-all:       ## TOUS les tests (property-based inclus, ~40s)
	$(PYTHON) -m unittest discover -s tests -v

test-gui:       ## tests Qt (offscreen). Ignorés si PySide6 est absent.
	QT_QPA_PLATFORM=offscreen $(PYTHON) -m pytest tests/test_gui.py -q

lint:           ## ruff check (lint) + ruff format --check (style)
	ruff check sentinel/ tests/
	ruff format --check sentinel/ tests/

typecheck:      ## mypy sur le paquet sentinel
	mypy

format:         ## ruff format (auto-corrige le style)
	ruff format sentinel/ tests/
	ruff check --fix sentinel/ tests/

check: test lint typecheck  ## alias : tests + lint + mypy

coverage:       ## couverture de tests (rapport texte)
	coverage run -m unittest discover -s tests
	coverage report

clean:          ## nettoie les artefacts (cache, build, .coverage, .hypothesis)
	rm -rf .hypothesis/ .coverage .coverage.* htmlcov/ coverage.xml \
	       build/ dist/ *.egg-info .pytest_cache/ .ruff_cache/ .mypy_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

run-scan:       ## exemple : scan d'un dossier (sentinel scan <folder>)
	$(PYTHON) -m sentinel scan $(FOLDER)

run-baseline:   ## exemple : crée une baseline (sentinel baseline <folder> --out <file>)
	$(PYTHON) -m sentinel baseline $(FOLDER) --out $(OUT)

pre-commit-install:  ## installe les hooks git (une seule fois par clone)
	pre-commit install

pre-commit-run:      ## lance les hooks sur tous les fichiers (debug)
	pre-commit run --all-files
