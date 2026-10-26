"""Process-wide deny-by-default network guard for the demo and private UI processes.

This is a guard against accidental Python networking and process creation through the
audited calls below, not an OS sandbox: deliberately written Python or native code can
bypass audit hooks (Python documents this), so it does not contain malicious code.
Install before opening the loopback listener. Never install in the test runner.
"""
import sys

# Native Keychain calls (keyring's macOS backend) resolve Security/CoreFoundation
# symbols lazily; every other dynamic symbol lookup after installation is refused.
_FRAMEWORKS = "/System/Library/Frameworks/"
_SYMBOL_PREFIXES = ("kSec", "kCF", "Sec", "CF")


def _denied(*_args, **_kwargs):
    raise PermissionError("Child processes are disabled in the mock server")


def deny_network(event, args):
    if event in {"socket.connect", "socket.connect_ex", "socket.getaddrinfo",
                 "socket.gethostbyname", "socket.gethostbyaddr", "socket.getnameinfo", "socket.sendto",
                 "socket.sendmsg"}:
        raise PermissionError("Local-only mode blocks all outbound network operations")
    if event == "socket.bind" and args[1][0] != "127.0.0.1":
        raise PermissionError("Only a literal IPv4 loopback listener is permitted")
    if event in {"subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork", "os.forkpty"}:
        raise PermissionError("Child processes are disabled in the mock server")
    if event == "ctypes.dlopen":
        raise PermissionError("Loading native libraries is disabled after startup")
    if event == "ctypes.dlsym":
        library, name = args[0], args[1]
        path = getattr(library, "_name", None)
        if not (isinstance(path, str) and path.startswith(_FRAMEWORKS) and
                isinstance(name, str) and name.startswith(_SYMBOL_PREFIXES)):
            raise PermissionError("Native symbol lookup is disabled after startup")


def install():
    sys.addaudithook(deny_network)
    # _posixsubprocess.fork_exec raises no audit event; multiprocessing's spawn path calls it
    # directly and would start an interpreter without this hook.
    import _posixsubprocess
    _posixsubprocess.fork_exec = _denied
