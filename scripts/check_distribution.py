"""Inspect a wheel before distribution. Build it outside the source checkout."""
import argparse
import re
import stat
import zipfile
from pathlib import PurePosixPath

from scripts.check_public_tree import PINNED_BINARIES, PINNED_LIMIT, audit


def check(path):
    mapped = {}
    metadata = []
    with zipfile.ZipFile(path) as wheel:
        for item in wheel.infolist():
            parts = PurePosixPath(item.filename).parts
            limit = PINNED_LIMIT if item.filename in PINNED_BINARIES else 180000
            if not parts or ".." in parts or item.filename.startswith("/") or item.file_size > limit or stat.S_ISLNK(item.external_attr >> 16):
                return ["invalid distribution path or size"]
            name = item.filename
            if ".dist-info/" in name:
                if not re.fullmatch(r"privacy_cleanup_local-[0-9A-Za-z.]+\.dist-info", parts[0]):
                    return ["invalid distribution metadata path"]
                relative = name.split(".dist-info/", 1)[1]
                if relative not in {"METADATA", "WHEEL", "RECORD", "entry_points.txt", "top_level.txt", "licenses/LICENSE"}:
                    return ["unreviewed distribution metadata"]
                metadata.append(wheel.read(item))
                continue
            if parts[0] != "privacy_cleanup":
                # Also keeps wheel content from colliding with the metadata scan key below.
                return ["unreviewed distribution path"]
            if name.startswith("privacy_cleanup/fixtures/"):
                name = "fixtures/" + name[len("privacy_cleanup/fixtures/"):]
            if name in mapped:
                return ["duplicate distribution entry"]
            mapped[name] = wheel.read(item)
    # Metadata is also content-scanned, without copying any archive data into Git.
    mapped["README.md"] = b"\n".join(metadata)
    return audit(mapped)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel")
    args = parser.parse_args()
    failures = check(args.wheel)
    if failures:
        for failure in sorted(set(failures)):
            print("FAIL:", failure)
        raise SystemExit(1)
    print("PASS: wheel paths, metadata, content and synthetic fixture seals")


if __name__ == "__main__":
    main()
