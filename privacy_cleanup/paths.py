"""Runtime path policy. No runtime file may be inside a source checkout."""
import os
import stat
from pathlib import Path

from .domain import RuleError

ROOT = Path(__file__).resolve().parent.parent


def validate_directory(path):
    raw = Path(path).expanduser().absolute()
    for p in (raw, *raw.parents):
        if p.is_symlink():
            raise RuleError("Private data directory must not contain symlinks")
    path = raw.resolve()
    if path == ROOT or ROOT in path.parents or path in ROOT.parents:
        raise RuleError("Private data must be separate from the source tree")
    if any((p / ".git").exists() for p in (path, *path.parents)):
        raise RuleError("Private data must be outside every Git checkout")
    if path.exists():
        info = path.stat()
        if not path.is_dir() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise RuleError("Existing private directory must be owned by you and mode 0700")
    return path


def open_directory(path):
    """Create/traverse with directory descriptors, refusing symlink components."""
    path = validate_directory(path)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            try:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                os.mkdir(component, 0o700, dir_fd=fd)
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        validate_directory(path)
        if (os.fstat(fd).st_dev, os.fstat(fd).st_ino) != (path.stat().st_dev, path.stat().st_ino):
            raise RuleError("Private directory changed; close the application")
        return path, fd
    except BaseException:
        os.close(fd)
        raise


def check_file(info):
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o077:
        raise RuleError("Private files must be owned, unlinked regular files with mode 0600")
