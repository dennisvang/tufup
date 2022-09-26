from unittest import TestCase

from packaging.version import Version
import tuf


class PackageTests(TestCase):
    def test_tuf_version(self):
        # quick & dirty regression test for issue 44
        self.assertGreaterEqual(Version(tuf.__version__), Version('2'))
