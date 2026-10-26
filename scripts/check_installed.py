"""Install a wheel without dependencies and smoke-test its demo outside the source."""
import argparse
import os
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import venv
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('wheel')
    args = parser.parse_args()
    wheel = str(Path(args.wheel).resolve())
    with tempfile.TemporaryDirectory(prefix='velum-installed-', dir='/private/tmp' if Path('/private/tmp').exists() else '/tmp') as directory:
        root = Path(directory)
        venv.EnvBuilder(with_pip=True).create(root / 'env')
        python = root / 'env/bin/python'
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        env.pop('PYTHONPATH', None)
        subprocess.run([str(python), '-m', 'pip', 'install', '--no-index', '--no-deps', wheel], cwd=root, env=env, check=True)
        for command in ('velum', 'privacy-cleanup'):
            subprocess.run([str(root / 'env/bin' / command), '--help'], cwd=root, env=env, check=True, stdout=subprocess.DEVNULL)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        process = subprocess.Popen([str(python), '-m', 'privacy_cleanup', '--port', str(port), '--data-dir', str(root / 'runtime')], cwd=root, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError('Installed demo exited before serving')
                try:
                    with urllib.request.urlopen('http://127.0.0.1:%d/' % port, timeout=1) as response:
                        page = response.read()
                    if b'Velum' not in page:
                        raise RuntimeError('Unexpected installed demo')
                    break
                except urllib.error.URLError:
                    time.sleep(.1)
            else:
                raise RuntimeError('Installed demo did not become ready')
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait()
    print('PASS: clean wheel install, both entry points and loopback demo; no private data or accounts')


if __name__ == '__main__':
    main()
