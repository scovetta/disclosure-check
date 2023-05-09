import unittest
from disclosurecheck.main import DisclosureCheck
import io
import json
from contextlib import redirect_stdout
from packageurl import PackageURL
import io
from contextlib import redirect_stdout, redirect_stderr
import os

import logging

logging.getLogger().setLevel(logging.DEBUG)

class TestEndToEndResults(unittest.TestCase):
    def test(self):
        self.maxDiff = 32768

        # Walk through files in data
        for root, dirs, files in os.walk("tests/disclosurecheck/data"):
            for _filename in files:
                if not _filename.endswith('.test'):
                    continue

                with open(os.path.join(root, _filename), 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    package_url = lines[0].strip()
                    expected_results = json.loads(''.join(lines[1:]))

                with (redirect_stdout(io.StringIO()) as _,
                      redirect_stderr(io.StringIO()) as _):
                    dc = DisclosureCheck(PackageURL.from_string(package_url))
                    dc.execute()
                    out = json.loads(dc.get_results_json())

                self.assertEqual(expected_results, out, os.path.join(root, _filename))

if __name__ == '__main__':
    unittest.main()