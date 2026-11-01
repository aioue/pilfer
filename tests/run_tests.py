#!/usr/bin/env python3
"""Run every test class in tests/. CI runs only this script.

Discovery, not a list of classes: a hand-kept list let a whole class
(TestReviewFollowups) go unrun in CI until 2.31.
"""

import os
import sys
import unittest


def main() -> int:
    tests_dir = os.path.dirname(os.path.abspath(__file__))
    suite = unittest.defaultTestLoader.discover(tests_dir, pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    # Discovery turns an import error into a failing test, so it is counted
    # below. An empty run would otherwise be green.
    if result.testsRun == 0:
        print("\n❌ No tests ran.")
        return 1
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
