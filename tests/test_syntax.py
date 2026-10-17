"""Every Python file must be valid Python 3.9 (the system python3 on Rocky/RHEL 9)."""

import ast
import glob
import os
import unittest

from tests import helpers


def python_files():
    files = glob.glob(os.path.join(helpers.ROOT, "dbovpn", "**", "*.py"), recursive=True)
    files += glob.glob(os.path.join(helpers.ROOT, "tests", "*.py"))
    files += [os.path.join(helpers.ROOT, "bin", n) for n in ("dbo-vpn-gateway", "privhelper")]
    return sorted(files)


class SyntaxTest(unittest.TestCase):
    def test_python39_grammar(self):
        files = python_files()
        self.assertGreater(len(files), 30)
        for path in files:
            with open(path, encoding="utf-8") as fh:
                src = fh.read()
            ast.parse(src, filename=path, feature_version=(3, 9))
            compile(src, path, "exec")


if __name__ == "__main__":
    unittest.main()
