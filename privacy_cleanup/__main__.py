import sys


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "recovery":
        sys.argv.pop(1)
        from .recovery import main as recover
        return recover()
    if len(sys.argv) > 1 and sys.argv[1] == "private":
        if sys.version_info < (3, 12) or sys.platform != "darwin":
            raise SystemExit("Private mode requires Python 3.12+ on macOS; the demo is still available.")
        sys.argv.pop(1)
        try:
            from .private_server import main as start
        except ImportError:
            raise SystemExit("Install the pinned private dependencies before starting private mode.") from None
    else:
        if len(sys.argv) > 1 and sys.argv[1] == "demo":
            sys.argv.pop(1)
        from .server import main as start
    start()


if __name__ == "__main__":
    main()
