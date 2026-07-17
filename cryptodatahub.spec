Name:           python-cryptodatahub
Version:        1.4.0
Release:        1%{?dist}
Summary:        Repository of cryptography-related data

License:        MPL-2.0
URL:            https://gitlab.com/coroner/cryptodatahub
Source0:        %{name}_%{version}.tar.xz

BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  python3-pip
BuildRequires:  python3-setuptools
BuildRequires:  python3-wheel

%description
CryptoDataHub is a database for cryptographic protocol data including
cipher suites, algorithm identifiers, TLS extension types, and related
constants used by the CryptoParser and CryptoLyzer analysis libraries.

%package -n python3-cryptodatahub
Summary:        %{summary}
Requires:       python3-asn1crypto
Requires:       python3-attrs
Requires:       python3-dateutil
Requires:       python3-urllib3

%description -n python3-cryptodatahub
CryptoDataHub is a database for cryptographic protocol data including
cipher suites, algorithm identifiers, TLS extension types, and related
constants used by the CryptoParser and CryptoLyzer analysis libraries.

%prep
%setup -q -T -c -n %{name}-%{version}
tar -xJf %{SOURCE0} --strip-components=1
sed -i "s/, 'setuptools-scm'//" pyproject.toml
sed -i "s/name = 'CryptoDataHub'/name = 'cryptodatahub'/" pyproject.toml

%build
export SETUPTOOLS_SCM_PRETEND_VERSION=%{version}

%install
export SETUPTOOLS_SCM_PRETEND_VERSION=%{version}
%{__python3} -m pip install --no-build-isolation --no-deps --root %{buildroot} --prefix %{_prefix} .

%check

%files -n python3-cryptodatahub
%{python3_sitelib}/cryptodatahub/
%{python3_sitelib}/cryptodatahub-%{version}.dist-info/
%{python3_sitelib}/updaters/
%{_bindir}/update-ct-log
%{_bindir}/update-trust-stores
%license LICENSE.txt

%changelog
* Fri Jul 17 2026 Szilárd Pfeiffer <coroner@pfeifferszilard.hu> - 1.4.0-1
- add IKE vendor IDs (#58)
- fix CAST-128 key size
- fix notify level of IKEv2 status types

* Mon Jun 15 2026 Szilárd Pfeiffer <coroner@pfeifferszilard.hu> - 1.3.0-1
- add elliptic-curve parameters (#53)
- add OpenJDK trusted root CA certificates (#54)
- add Debian and RPM packaging (#56)
- add IKE version definition (#55)
- add per-implementation names to algorithm entries (#55)
- add Blowfish block cipher (#39)
- add MARS block cipher (#40)
- add RC6 block cipher (#40)
- add Serpent block cipher (#40)
- add Twofish block cipher (#40)
- add AES CTR, CCM, and GCM cipher modes (#39)
- add Camellia CTR and CCM cipher modes (#39)
- add GCM-8 cipher mode for shortened ICV (#39)
- add GMAC cipher mode (#39)
- add AES-XCBC and AES-CMAC MAC entries (#40)
- add AEAD attribute to encryption algorithms, block ciphers, and cipher modes (#40)
- fix Chacha20 key size (#39)
- fix CAST block cipher variant naming (#39)
- split Triple DES into 112-bit and 168-bit variants (#39)
- map IKEv1 RFC 5114 Diffie-Hellman subgroups to their own parameters (#39)
