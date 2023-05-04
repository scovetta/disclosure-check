SHELL := /bin/bash
PROJECT_VERSION := $(shell grep -m1 version pyproject.toml | cut -d\" -f2)

.ONESHELL:

all: build test-dist

test:
	python -m unittest discover -s tests.disclosurecheck -t .

build: clean
	@echo "Initializing environment..."
	python -mvenv _tmpvenv
	source _tmpvenv/bin/activate
	pip install -r requirements.txt -r dev-requirements.txt

	@echo "Building distribution..."
	python -mbuild .

	@echo "Building container image..."
	docker build -t disclosurecheck:$(PROJECT_VERSION) .

	echo "Cleaning up temporary environment"
	deactivate
	rm -rf _tmpvenv

test-dist: build
	@echo "Validating distribution..."
	python -mvenv _tmpvenv
	source _tmpvenv/bin/activate

	pip install dist/disclosurecheck-*.tar.gz
	disclosurecheck --help

	echo "Cleaning up temporary environment"
	deactivate
	rm -rf _tmpvenv

	echo "Validating image..."
	docker run --rm -t disclosurecheck:$(PROJECT_VERSION) --help

clean:
	@echo "Cleaning up temporary environment"
	deactivate || true
	rm -rf dist/* || true
	rm -rf _tmpvenv || true


