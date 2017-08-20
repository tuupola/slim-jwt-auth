.DEFAULT_GOAL := help

help:
	@echo ""
	@echo "Available tasks:"
	@echo "    lint   Run linter and code style checker"
	@echo "    unit   Run unit tests and generate coverage"
	@echo "    test   Run linter and unit tests"
	@echo "    watch  Run linter and unit tests when any of the source files change"
	@echo "    deps   Install dependencies"
	@echo "    all    Install dependencies and run linter and unit tests"
	@echo ""

deps:
	composer install --prefer-dist

lint:
	vendor/bin/phplint . --exclude=vendor/
	vendor/bin/phpcs -p --standard=PSR2 --extensions=php --encoding=utf-8 --ignore=*/vendor/*,*/benchmarks/* .

unit:
	vendor/bin/phpunit --coverage-text --coverage-clover=coverage.xml --coverage-html=./report/

watch:
	find . -name "*.php" -not -path "./vendor/*" -o -name "*.json" -not -path "./vendor/*" | entr -c make test

test: lint unit

travis: lint unit

all: deps test

.PHONY: help deps lint test watch all
