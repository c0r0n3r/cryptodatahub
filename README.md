[![Pipeline](https://gitlab.com/coroner/cryptodatahub/badges/master/pipeline.svg)](https://gitlab.com/coroner/cryptodatahub/-/pipelines/master/latest)
[![Test Coverage](https://coveralls.io/repos/gitlab/coroner/cryptodatahub/badge.svg?branch=master)](https://coveralls.io/gitlab/coroner/cryptodatahub/)
[![Documentation](https://readthedocs.org/projects/cryptodatahub/badge/?version=latest)](https://cryptodatahub.readthedocs.io)

<!-- documentation-summary-start -->
**CryptoDataHub** is a repository of cryptography-related data available under a free license. The main goal of the
repository is to support cryptographic library tester and client/server cryptographic settings analyzer applications
such as [CryptoLyzer](https://cryptolyzer.readthedocs.io/) with reliable and freely available data.

**Use CryptoDataHub when you need algorithm identifiers** — public key, digital signature, key exchange, block cipher,
stream cipher, cryptographic hash, elliptic-curve, and message authentication code algorithms are available as
enumerations with their code points, names, and parameters.

**Use CryptoDataHub when you need Diffie-Hellman parameters** — both the finite field parameters defined by
[RFC 2539](https://www.rfc-editor.org/rfc/rfc2539.html#appendix-A),
[RFC 3526](https://www.rfc-editor.org/rfc/rfc3526.html),
[RFC 5114](https://www.rfc-editor.org/rfc/rfc5114.html), and
[RFC 7919](https://www.rfc-editor.org/rfc/rfc7919.html#appendix-A), and the ones built into Apache HTTP Server,
HAProxy, Postfix, ProFTPD, and socat.

**Use CryptoDataHub when you need trust stores** — the trusted root certification authority certificate stores of
Android, Apple, Google Chrome, Microsoft, Mozilla, OpenJDK, and Oracle, and the Certificate Transparency log list.

**Use CryptoDataHub when you need vulnerability data** — the algorithms and parameters affected by D(HE)at, Logjam,
Sweet32, Shatter, and Weak DH are marked in the data itself.
<!-- documentation-summary-end -->

<!-- documentation-strength-start -->
The strength of CryptoDataHub is that the data is machine-readable, versioned, and updated from its original sources by
the updaters shipped with the repository, so a consumer does not have to scrape registries, vendor pages, or trust
store exports on its own.
<!-- documentation-strength-end -->

## Why CryptoDataHub?

<!-- documentation-comparison-start -->
- **Free license** — the data is available under the same license as the code, without a per-consumer agreement.
- **One source for several protocols** — protocol-independent algorithm data and the protocol-dependent attributes of
  IKE, SSL, TLS, SSH, and DNSSEC live in one repository.
- **Wrapper included** — the data ships with a Python wrapper, so it can be consumed as typed enumerations instead of
  as raw JSON.
- **Reproducible updates** — `update-ct-log` and `update-trust-stores` regenerate the data from its original sources.
<!-- documentation-comparison-end -->

## Usage

### uv

```shell
uv add cryptodatahub
```

```python
from cryptodatahub.tls.algorithm import TlsCipherSuite

# look up a cipher suite by its code point
TlsCipherSuite.from_code(0x1301)
# TlsCipherSuite.TLS_AES_128_GCM_SHA256
```

## Support

**Python implementations**

- CPython 3.9+
- PyPy 3.9+

**Operating systems**

- Linux
- macOS
- Windows

## Documentation

Detailed [documentation](https://cryptodatahub.readthedocs.io) is available on the project's
[Read the Docs](https://readthedocs.com) site.

## License

The [code](https://gitlab.com/coroner/cryptodatahub) is available under the terms of
[Mozilla Public License Version 2.0](https://www.mozilla.org/en-US/MPL/2.0/) (MPL 2.0).

A non-comprehensive but straightforward description of MPL 2.0 can be found at the
[Choose an open source license](https://choosealicense.com/licenses#mpl-2.0) website.

## Credits

- [NLnet Foundation](https://nlnet.nl) and [NGI Assure](https://www.assure.ngi.eu), supports the project part of the
  [Next Generation Internet](https://ngi.eu) initiative.
