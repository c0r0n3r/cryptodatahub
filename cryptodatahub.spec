Name:           python-cryptodatahub
Version:        1.2.1
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
