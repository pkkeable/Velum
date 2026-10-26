"""Run the complete suite and optionally reject dependency-driven skips."""
import argparse
import unittest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-private', action='store_true')
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.discover('tests')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if args.require_private and result.skipped:
        print('FAIL: fully provisioned test lane must not skip tests')
        raise SystemExit(1)
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == '__main__':
    main()
