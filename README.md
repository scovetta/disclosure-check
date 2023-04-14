# disclosure-check
PoC for detecting disclosure mechanisms for open source projects

### Usage

```
git clone https://github.com/scovetta/disclosure-check
cd disclosure-check
python -mvenv venv
source venv/bin/activate
pip install -r requirements.txt

python -m disclosurecheck.check pkg:pypi/django

python -m disclosurecheck.check --help

usage: OpenSSF Vulnerability Disclosure Mechanism Detector [-h] [--verbose] [--json] package_url

positional arguments:
  package_url  Package URL for the project/package you want to analyze.

options:
  -h, --help   show this help message and exit
  --verbose    Show extra logging.
  --json       Output as JSON.
 ```

 ### Screenshot

<img width="491" alt="Screenshot 2023-04-13 003734" src="https://user-images.githubusercontent.com/732166/231688054-e159fe50-1b2f-4fa3-bb93-70fe8947e19a.png">
