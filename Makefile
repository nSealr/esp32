.PHONY: setup test lint audit docs ci

setup:
	@echo "No setup required until the ESP-IDF project is introduced."

test:
	python3 scripts/verify_repo.py

lint:
	python3 scripts/verify_repo.py

audit:
	python3 scripts/verify_repo.py

docs:
	python3 scripts/verify_repo.py

ci: setup test lint audit docs

