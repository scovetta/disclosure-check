#!/bin/bash

python -m unittest discover -s tests.disclosurecheck -t .

deactivate
rm dist/*
source venv/bin/activate
python -mbuild .

rm -rf ../venv1
python -mvenv ../venv1
source ../venv1/bin/activate
pip install dist/disclosurecheck-*.tar.gz

disclosurecheck --help

VERSION=$(cat pyproject.toml| grep version | cut -d\" -f2)
docker build -t disclosurecheck:$VERSION .