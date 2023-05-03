import unittest
from  disclosurecheck.util.normalize import sanitize_github_url

class TestSanitizeGithubUrlMethods(unittest.TestCase):
    EXPECTED_RESULTS = [
        ('foo', None),
        (None, None),
        ('https://github.com/foo/bar', 'https://github.com/foo/bar'),
        ('https://github.com/foo/bar#quux', 'https://github.com/foo/bar'),
        ('https://github.com/foo/bar?a=b', 'https://github.com/foo/bar'),
        ('https://github.com/foo/bar?a=b&c=d', 'https://github.com/foo/bar'),
        ('https://github.com/foo/bar?a=b&c=d#efg;hij.klm', 'https://github.com/foo/bar'),
        ('https://github.com/foo/bar?a=b&c=d#test.git', 'https://github.com/foo/bar'),
        ('https://github.com/foo/bar.git', 'https://github.com/foo/bar'),
        ('https://github.com/foo/bar.git#quux', 'https://github.com/foo/bar'),
        ('https://github.com/foo/bar.git?a=b', 'https://github.com/foo/bar'),
        ('https://github.com/foo/bar.git?a=b&c=d', 'https://github.com/foo/bar'),
        ('https://github.com/foo/bar.git?a=b&c=d#efg;hij.klm', 'https://github.com/foo/bar'),
        ('https://github.com/foo/bar.git?a=b&c=d#test.git', 'https://github.com/foo/bar'),
        ('https://github.com/foo/bar/issues', 'https://github.com/foo/bar'),
        ('https://github.com/foo/bar/SECURITY.md', 'https://github.com/foo/bar'),
        ('https://github.com/foo/bar/blob/main/README.md', 'https://github.com/foo/bar'),
        ('http://github.com/foo/bar.git?a=b&c=d#test.git', 'https://github.com/foo/bar'),
        ('https://raw.github.com/foo/bar/SECURITY.md', 'https://github.com/foo/bar'),
        ('https://raw.githubusercontent.com/foo/bar/SECURITY.md', 'https://github.com/foo/bar'),
        ('https://bitbucket.org', None),
        ('ssh://git@github.com/foo/bar', 'https://github.com/foo/bar'),
        ('ssh://git@github.com/foo/bar#quux', 'https://github.com/foo/bar'),
        ('ssh://github.com/foo/bar#quux', 'https://github.com/foo/bar'),
        ('ssh://github.com/foo/bar#quux', 'https://github.com/foo/bar'),
        ('git://github.com/foo/bar.git', 'https://github.com/foo/bar'),
        ('git://github.com/foo/bar.git/', 'https://github.com/foo/bar'),
        ('ftp://github.com/foo/bar.git/', 'https://github.com/foo/bar'),
        ('ftps://github.com/foo/bar.git/', 'https://github.com/foo/bar'),
        ('github.com/foo/bar.git/', 'https://github.com/foo/bar'),
    ]

    def test(self):
        for result in self.EXPECTED_RESULTS:
            self.assertEqual(sanitize_github_url(result[0]), result[1], result)

if __name__ == '__main__':
    unittest.main()