[![Scorecard supply-chain security](https://github.com/scovetta/disclosure-check/actions/workflows/scorecards.yml/badge.svg)](https://github.com/scovetta/disclosure-check/actions/workflows/scorecards.yml)

# Disclosure Check

Disclosure Check is a tool for identifying vulnerability disclosure mechanisms for open source projects.

![disclosure-check](https://user-images.githubusercontent.com/732166/236118411-f69f85cf-d10a-45a7-b4cf-e9c6b4171788.gif)

## Why the tool is needed

Most open source projects use a public issuer tracker for inbound requests, bug reports, etc. Since this is inappropriate
for reporting new vulnerabilities, many projects have other mechanisms for users to submit sensitive reports.

Unfortunately, there is no widely-used, machine-readable way to discover this for a given project. Instead, a human might
need to look for a SECURITY.md file (and read through it), review a README.md, check to see if a private vulnerability
reporting mechanism is available through the source repository, check to see if an e-mail address is associated with the
published package, etc.

This is time consuming for one project, and far more so when done at scale.

The purpose of Disclosure Check is to automate what a human would do when trying to discover the best way to report
a vulnerability to a project. It's use is orthogonal to the goal of more standardized reporting mechanisms; if and when
the later becomes a reality, this tool will no longer be useful.

## Installation

### Requirements

Disclosure Check is available through PyPI and Docker Hub. If you install through PyPI, you'll also need to install
[OSS Gadget](https://github.com/Microsoft/OSSGadget), which is needed to download the package contents for analysis.


### PyPI

#### Installing OSS Gadget

Refer to the [OSS Gadget](https://github.com/Microsoft/OSSGadget) page for up to date installation instructions.

You can then install Disclosure Check from PyPI:

```
pip install disclosurecheck
```

You should always install packages like this in a virtual environment since installation will include other dependencies.

### Docker

You can create a local Docker image by running:

```
docker build -t disclosurecheck:latest .
```

## Usage

To run Disclosure Check:

```
disclosurecheck --help

usage: OpenSSF Vulnerability Disclosure Mechanism Detector [-h] [--verbose] [--json] package_url

positional arguments:
  package_url  Package URL for the project/package you want to analyze.

options:
  -h, --help   show this help message and exit
  --verbose    Show extra logging.
  --json       Output as JSON.
 ```
