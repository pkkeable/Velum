# Third-party notices

Velum source retains its existing MIT license (see the distribution LICENSE).
The bundled, unmodified EB Garamond variable font is separately licensed under
SIL OFL 1.1; its copyright and complete terms are in static/fonts/OFL.txt. Its
reviewed SHA-256 is ef9512f92f6d579e5dc75af59a5a4b1b8b47d2eda89e00b954d44520e5369027.
These notices do not relicense the font or dependencies.

Optional dependencies are installed separately, not vendored in Velum's wheel.
Retain their original distribution notices when redistributing their wheels:

| Dependency | Pinned version | Upstream license |
| --- | --- | --- |
| cryptography | 50.0.1 | Apache-2.0 OR BSD-3-Clause; bundled native components have additional notices in its wheel |
| cffi | 2.1.1 | MIT-0 |
| pycparser | 3.0 | BSD-3-Clause |
| keyring | 25.7.0 | MIT |
| jaraco.classes | 3.4.0 | MIT (wheel LICENSE) |
| jaraco.context | 6.1.2 | MIT |
| jaraco.functools | 4.6.0 | MIT |
| more-itertools | 11.1.0 | MIT |

Build backend: setuptools 84.1.0 (MIT). Version-specific provenance and advisory
metadata: https://pypi.org/pypi/NAME/VERSION/json. Hashes for the supported native
wheels remain in the two requirements-private lock files. Checked 2026-10-17;
absence of a listed advisory is not proof of absence of vulnerabilities.
