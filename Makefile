.PHONY: check lint typecheck test format

check: lint typecheck test  ## Run all checks (lint + types + tests)

lint:  ## Run ruff linter
	ruff check .

typecheck:  ## Run mypy type checker
	mypy sentinel/

test:  ## Run pytest
	python -m pytest tests/ -q

format:  ## Auto-format with ruff
	ruff format .
	ruff check --fix .

register:  ## Register bot commands with Telegram autocomplete
	python telegram-commander.py --register-commands
