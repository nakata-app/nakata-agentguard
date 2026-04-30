.PHONY: install test lint fmt bench clean

install:
	pip install -e ".[dev,serve]"

test:
	pytest tests/ -v --cov=agentguard --cov-report=term-missing

lint:
	ruff check src/ tests/

fmt:
	ruff format src/ tests/

bench:
	python benchmarks/bench_guard.py

clean:
	rm -rf dist/ build/ *.egg-info .coverage htmlcov/ .pytest_cache/
