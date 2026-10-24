# Third-party dependency notices

This inventory describes a Windows / Python 3.14 resolution made on 2026-10-22.
Versions permitted by open requirements can resolve differently later or on other platforms.
The packages below are installed separately; their wheels and source trees are not vendored
in Bughunt's source distribution. Each package keeps its own license. Source distributions
and wheels linked below contain the authoritative license files and notices.

The minimal scope is the package's core install. Hardened and source scopes describe the
pinned setup and broad checkout requirements. Screenshots, Tor, pipeline YAML and flowcarve
are separate capability scopes; flowcarve adds the optional mitmproxy dependency tree.

## Distribution boundaries

Certifi includes MPL-2.0 certificate data. Optional publicsuffix2 includes MPL-2.0 material.
The optional flowcarve tree includes ldap3 (LGPL v3), mitmproxy-windows (LGPL-3.0-or-later),
urwid (LGPL-2.1-only), and pydivert (LGPL-3.0-or-later OR GPL-2.0-or-later).
These dependencies are not included in the Bughunt wheel. A container, frozen executable
or other distribution bundling dependencies needs its own complete license and notice review.

Playwright's wheel includes a Node driver and third-party notices. Browser downloads, ZAP,
Burp and other separately installed engines carry their own terms. This inventory does not
license or bundle those external runtimes. Preserve their supplied licenses when distributing them.

The mitmproxy-rs 0.12.15 wheel declares MIT in its shipped CycloneDX SBOM. Its Rust components
carry individual licenses: self_cell offers Apache-2.0 OR GPL-2.0-only, r-efi offers MIT OR
Apache-2.0 OR LGPL-2.1-or-later, and internet-checksum's embedded license text is BSD-2-Clause.
This source-only dependency record is an engineering inventory, not a legal certification.

## Resolved packages

| Distribution | Version | Declared license / evidence | Install scopes |
| --- | --- | --- | --- |
| [aiohappyeyeballs](https://pypi.org/project/aiohappyeyeballs/2.7.1/) | 2.7.1 | PSF-2.0 | flowcarve, source |
| [aiohttp](https://pypi.org/project/aiohttp/3.14.5/) | 3.14.5 | Apache-2.0 AND MIT | flowcarve, source |
| [aioquic](https://pypi.org/project/aioquic/1.2.0/) | 1.2.0 | BSD-3-Clause | flowcarve |
| [aiosignal](https://pypi.org/project/aiosignal/1.4.0/) | 1.4.0 | Apache 2.0 | flowcarve, source |
| [anyio](https://pypi.org/project/anyio/4.15.1/) | 4.15.1 | MIT | flowcarve, hardened, minimal, pipeline-yaml, screenshots, source, tor |
| [argon2-cffi](https://pypi.org/project/argon2-cffi/25.1.0/) | 25.1.0 | MIT | flowcarve |
| [argon2-cffi-bindings](https://pypi.org/project/argon2-cffi-bindings/26.1.0/) | 26.1.0 | MIT | flowcarve |
| [asgiref](https://pypi.org/project/asgiref/3.12.1/) | 3.12.1 | BSD-3-Clause | flowcarve |
| [attrs](https://pypi.org/project/attrs/26.1.0/) | 26.1.0 | MIT | flowcarve, source |
| [bcrypt](https://pypi.org/project/bcrypt/5.0.0/) | 5.0.0 | Apache-2.0 | flowcarve |
| [blinker](https://pypi.org/project/blinker/1.9.0/) | 1.9.0 | MIT License | flowcarve |
| [brotli](https://pypi.org/project/brotli/1.2.0/) | 1.2.0 | MIT | flowcarve |
| [certifi](https://pypi.org/project/certifi/2026.10.19/) | 2026.10.19 | MPL-2.0 | flowcarve, hardened, minimal, pipeline-yaml, screenshots, source, tor |
| [cffi](https://pypi.org/project/cffi/2.1.1/) | 2.1.1 | MIT-0 | flowcarve |
| [charset-normalizer](https://pypi.org/project/charset-normalizer/3.5.2/) | 3.5.2 | MIT | flowcarve, source |
| [click](https://pypi.org/project/click/8.5.0/) | 8.5.0 | BSD-3-Clause | flowcarve |
| [colorama](https://pypi.org/project/colorama/0.4.6/) | 0.4.6 | BSD License | flowcarve, source |
| [cryptography](https://pypi.org/project/cryptography/50.0.2/) | 50.0.2 | Apache-2.0 OR BSD-3-Clause | flowcarve |
| [Flask](https://pypi.org/project/Flask/3.1.3/) | 3.1.3 | BSD-3-Clause | flowcarve |
| [frozenlist](https://pypi.org/project/frozenlist/1.8.0/) | 1.8.0 | Apache-2.0 | flowcarve, source |
| [greenlet](https://pypi.org/project/greenlet/3.5.6/) | 3.5.6 | MIT AND PSF-2.0 | flowcarve, hardened, screenshots, source |
| [h11](https://pypi.org/project/h11/0.16.0/) | 0.16.0 | MIT | flowcarve, hardened, minimal, pipeline-yaml, screenshots, source, tor |
| [h2](https://pypi.org/project/h2/4.4.1/) | 4.4.1 | MIT | flowcarve |
| [hpack](https://pypi.org/project/hpack/4.2.0/) | 4.2.0 | MIT | flowcarve |
| [httpcore](https://pypi.org/project/httpcore/1.0.9/) | 1.0.9 | BSD-3-Clause | flowcarve, hardened, minimal, pipeline-yaml, screenshots, source, tor |
| [httpx](https://pypi.org/project/httpx/0.28.1/) | 0.28.1 | BSD-3-Clause | flowcarve, hardened, minimal, pipeline-yaml, screenshots, source, tor |
| [hyperframe](https://pypi.org/project/hyperframe/6.1.0/) | 6.1.0 | MIT License | flowcarve |
| [idna](https://pypi.org/project/idna/3.20/) | 3.20 | BSD-3-Clause | flowcarve, hardened, minimal, pipeline-yaml, screenshots, source, tor |
| [itsdangerous](https://pypi.org/project/itsdangerous/2.2.0/) | 2.2.0 | BSD License | flowcarve |
| [Jinja2](https://pypi.org/project/Jinja2/3.1.6/) | 3.1.6 | BSD License | flowcarve |
| [kaitaistruct](https://pypi.org/project/kaitaistruct/0.11/) | 0.11 | MIT | flowcarve |
| [ldap3](https://pypi.org/project/ldap3/2.9.1/) | 2.9.1 | LGPL v3 | flowcarve |
| [linkify-it-py](https://pypi.org/project/linkify-it-py/2.2.0/) | 2.2.0 | MIT | flowcarve, hardened, source |
| [markdown-it-py](https://pypi.org/project/markdown-it-py/4.2.0/) | 4.2.0 | MIT License | flowcarve, hardened, minimal, pipeline-yaml, screenshots, source, tor |
| [MarkupSafe](https://pypi.org/project/MarkupSafe/3.0.4/) | 3.0.4 | BSD-3-Clause | flowcarve |
| [mdit-py-plugins](https://pypi.org/project/mdit-py-plugins/0.6.1/) | 0.6.1 | MIT License | flowcarve, hardened, source |
| [mdurl](https://pypi.org/project/mdurl/0.1.2/) | 0.1.2 | MIT License | flowcarve, hardened, minimal, pipeline-yaml, screenshots, source, tor |
| [mitmproxy](https://pypi.org/project/mitmproxy/12.3.0/) | 12.3.0 | MIT License | flowcarve |
| [mitmproxy_rs](https://pypi.org/project/mitmproxy_rs/0.12.15/) | 0.12.15 | MIT (wheel-shipped SBOM) | flowcarve |
| [mitmproxy-windows](https://pypi.org/project/mitmproxy-windows/0.12.15/) | 0.12.15 | LGPL-3.0-or-later | flowcarve |
| [multidict](https://pypi.org/project/multidict/7.1.0/) | 7.1.0 | Apache-2.0 | flowcarve, source |
| [platformdirs](https://pypi.org/project/platformdirs/4.13.0/) | 4.13.0 | MIT | flowcarve, hardened, source |
| [playwright](https://pypi.org/project/playwright/1.63.0/) | 1.63.0 | Apache-2.0 | flowcarve, hardened, screenshots, source |
| [propcache](https://pypi.org/project/propcache/0.5.4/) | 0.5.4 | Apache-2.0 | flowcarve, source |
| [publicsuffix2](https://pypi.org/project/publicsuffix2/2.20191221/) | 2.20191221 | MIT and MPL-2.0 | flowcarve |
| [pyasn1](https://pypi.org/project/pyasn1/0.6.4/) | 0.6.4 | BSD-2-Clause | flowcarve |
| [pycparser](https://pypi.org/project/pycparser/3.12/) | 3.12 | BSD-3-Clause | flowcarve |
| [pydivert](https://pypi.org/project/pydivert/3.1.3/) | 3.1.3 | LGPL-3.0-or-later OR GPL-2.0-or-later | flowcarve |
| [pyee](https://pypi.org/project/pyee/13.0.1/) | 13.0.1 | MIT | flowcarve, hardened, screenshots, source |
| [Pygments](https://pypi.org/project/Pygments/2.21.0/) | 2.21.0 | BSD-2-Clause | flowcarve, hardened, minimal, pipeline-yaml, screenshots, source, tor |
| [pylsqpack](https://pypi.org/project/pylsqpack/0.3.24/) | 0.3.24 | BSD-3-Clause | flowcarve |
| [pyOpenSSL](https://pypi.org/project/pyOpenSSL/26.4.0/) | 26.4.0 | Apache License, Version 2.0 | flowcarve |
| [pyparsing](https://pypi.org/project/pyparsing/3.3.3/) | 3.3.3 | MIT | flowcarve |
| [pyperclip](https://pypi.org/project/pyperclip/1.11.0/) | 1.11.0 | BSD | flowcarve |
| [PyYAML](https://pypi.org/project/PyYAML/6.0.3/) | 6.0.3 | MIT | pipeline-yaml |
| [requests](https://pypi.org/project/requests/2.34.2/) | 2.34.2 | Apache-2.0 | flowcarve, source |
| [rich](https://pypi.org/project/rich/15.0.0/) | 15.0.0 | MIT | flowcarve, hardened, minimal, pipeline-yaml, screenshots, source, tor |
| [ruamel.yaml](https://pypi.org/project/ruamel.yaml/0.19.1/) | 0.19.1 | MIT | flowcarve |
| [service-identity](https://pypi.org/project/service-identity/26.1.0/) | 26.1.0 | MIT | flowcarve |
| [socksio](https://pypi.org/project/socksio/1.0.0/) | 1.0.0 | MIT License | flowcarve, hardened, source, tor |
| [sortedcontainers](https://pypi.org/project/sortedcontainers/2.4.0/) | 2.4.0 | Apache 2.0 | flowcarve |
| [textual](https://pypi.org/project/textual/8.2.8/) | 8.2.8 | MIT | flowcarve, hardened, source |
| [tornado](https://pypi.org/project/tornado/6.5.10/) | 6.5.10 | Apache-2.0 | flowcarve |
| [typing_extensions](https://pypi.org/project/typing_extensions/4.16.0/) | 4.16.0 | PSF-2.0 | flowcarve, hardened, minimal, pipeline-yaml, screenshots, source, tor |
| [tzdata](https://pypi.org/project/tzdata/2026.3/) | 2026.3 | Apache-2.0 | flowcarve, hardened, minimal, pipeline-yaml, screenshots, source, tor |
| [urllib3](https://pypi.org/project/urllib3/2.8.0/) | 2.8.0 | MIT | flowcarve, source |
| [urwid](https://pypi.org/project/urwid/4.0.13/) | 4.0.13 | LGPL-2.1-only | flowcarve |
| [wcwidth](https://pypi.org/project/wcwidth/0.9.3/) | 0.9.3 | MIT License | flowcarve |
| [websockets](https://pypi.org/project/websockets/15.0.1/) | 15.0.1 | BSD-3-Clause | flowcarve, hardened, source |
| [Werkzeug](https://pypi.org/project/Werkzeug/3.1.9/) | 3.1.9 | BSD-3-Clause | flowcarve |
| [wsproto](https://pypi.org/project/wsproto/1.3.2/) | 1.3.2 | MIT | flowcarve |
| [yarl](https://pypi.org/project/yarl/1.25.1/) | 1.25.1 | Apache-2.0 | flowcarve, source |
