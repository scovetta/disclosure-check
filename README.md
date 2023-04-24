[![Scorecard supply-chain security](https://github.com/scovetta/disclosure-check/actions/workflows/scorecards.yml/badge.svg)](https://github.com/scovetta/disclosure-check/actions/workflows/scorecards.yml)

# Disclosure Check
A tool for detecting disclosure mechanisms for open source projects

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

 ### Screenshot

![image](https://user-images.githubusercontent.com/732166/233898773-04640a44-e3fb-4c79-9f48-8aa83287ee85.png)
