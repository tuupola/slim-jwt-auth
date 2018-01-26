.DEFAULT_GOAL := help

help:
	@echo ""
	@echo "Available tasks:"
	@echo "    lint     Run linter and code style checker"
	@echo "    unit     Run unit tests and generate coverage"
	@echo "    static   Run static analysis"
	@echo "    test     Run linter, static analysis and unit tests"
	@echo "    watch    Run above when a source file changes"
	@echo "    deps     Install latest dependencies"
	@echo "    lowdeps  Install lowest allowed dependencies"
	@echo "    all      Install dependencies and run all tests"
	@echo ""

deps:
	composer update --prefer-dist

lowdeps:
	composer update --prefer-lowest --prefer-stable --prefer-dist

lint:
	vendor/bin/phplint . --exclude=vendor/
	vendor/bin/phpcs -p --standard=PSR2 --extensions=php --encoding=utf-8 --ignore=*/vendor/*,*/benchmarks/* .

unit:
	vendor/bin/phpunit --coverage-text --coverage-clover=coverage.xml --coverage-html=./report/

static:
	vendor/bin/phpstan analyse src --level max

watch:
	find . -name "*.php" -not -path "./vendor/*" -o -name "*.json" -not -path "./vendor/*" | entr -c make test

test: lint static unit

travis: lint static unit

all: deps test

.PHONY: help deps lint test watch all
