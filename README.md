[![Scorecard supply-chain security](https://github.com/scovetta/disclosure-check/actions/workflows/scorecards.yml/badge.svg)](https://github.com/scovetta/disclosure-check/actions/workflows/scorecards.yml)

# Disclosure Check
A tool for detecting disclosure mechanisms for open source projects

![disclosure-check](https://user-images.githubusercontent.com/732166/236118411-f69f85cf-d10a-45a7-b4cf-e9c6b4171788.gif)

### Usage

Download the latest .tar.gz file from the releases page.

```
$ pip install disclosurecheck-VERSION.tar.gz
$ disclosurecheck --help

usage: OpenSSF Vulnerability Disclosure Mechanism Detector [-h] [--verbose] [--json] package_url

positional arguments:
  package_url  Package URL for the project/package you want to analyze.

options:
  -h, --help   show this help message and exit
  --verbose    Show extra logging.
  --json       Output as JSON.
 ```
 
