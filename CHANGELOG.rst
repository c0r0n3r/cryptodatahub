=========
Changelog
=========

-------------------
1.0.1 - 2025-12-07
-------------------

Improvements
============

-  Generic

   -  add missing PQC named curves

      | ``SecP384r1MLKEM1024``

-  SSH

   -  add missing hybrid streamlined NTRU prime KEX algorithms (#33)

      | ``sntrup761x25519-sha512``

   -  add PQ/T hybrid key exchange algorithms with ML-KEM

      | ``mlkem768nistp256-sha256``, ``mlkem1024nistp384-sha384``, ``mlkem768x25519-sha256``

-------------------
1.0.0 - 2025-01-05
-------------------

Refactor
========

-  Generic

   -  Support only Python version greater or euqal than 3.9
   -  Use pyproject.toml instead of setup.py

-------------------
0.12.6 - 2024-12-08
-------------------

Features
========

-  Generic

   -  add certificate transparency (CT) logs (#24)

Improvements
============

-  Generic

   -  add elliptic-curve parameters (#24)

   -  add missing PQC named curves (#29)

      | ``SecP256r1MLKEM768``, ``X25519MLKEM768``

-  TLS

   -  add missing PQC named curves (#29)

      | ``SECP256R1_ML_KEM_768``, ``X25519_ML_KEM_768``

   -  add capabilities for Firefox version 108-133 (#30)

-------------------
0.12.5 - 2024-05-25
-------------------

Improvements
============

-  Generic

   -  add missing PQC named curves (#25)

      | ``Kyber-512-r3``, ``Kyber-768-r3``, ``Kyber-1024-r3``, ``secp256r1/Kyber-512-r3``,
      | ``secp256r1/Kyber-768-r3``, ``secp384r1/Kyber-768-r3``,
      | ``secp384r1/Kyber-1024-r3``

   -  test on Python 3.13 RC

-  TLS

   -  add missing PQC named curves (#25)

      | ``KYBER_512_R3``, ``KYBER_768_R3``, ``KYBER_1024_R3``, ``SECP256R1_KYBER_512_R3``,
      | ``SECP256R1_KYBER_768_R3``, ``SECP384R1_KYBER_768_R3``,
      | ``SECP521R1_KYBER_1024_R3``, ``X25519_KYBER_512_R3``, ``X25519_KYBER_768_R3``

-------------------
0.12.4 - 2024-04-28
-------------------

Features
========

-  TLS

   -  add supported protocol version to clients (#23)

-------------------
0.12.3 - 2024-03-05
-------------------

Notable fixes
=============

-  TLS

   -  fix MAC values of TLS 1.3 cipher suites (#21)

-------------------
0.12.2 - 2024-01-11
-------------------

Improvements
============

-  Generic

   -  add metadata to documentation
   -  add getter for well-know DH parameter by parameter numbers

-------------------
0.12.1 - 2023-12-13
-------------------

Improvements
============

-  SSH

   -  add missing host key algorithms (#16)

      | ``ecdsa-sha2-curve25519``, ``ecdsa-sha2-nistb233``, ``ecdsa-sha2-nistb409``,
      | ``ecdsa-sha2-nistk163``, ``ecdsa-sha2-nistk233``, ``ecdsa-sha2-nistk283``,
      | ``ecdsa-sha2-nistk409``, ``ecdsa-sha2-nistp192``, ``ecdsa-sha2-nistp224``,
      | ``ecdsa-sha2-nistt571``, ``ssh-dsa``, ``ssh-gost2001``, ``ssh-gost2012-256``,
      | ``ssh-gost2012-512``, ``ssh-rsa-sha2-256``,
      | ``ssh-rsa-sha2-256@attachmate.com``, ``ssh-rsa-sha2-512``,
      | ``ssh-xmss-cert-v01@openssh.com``, ``ssh-xmss@openssh.com``,
      | ``webauthn-sk-ecdsa-sha2-nistp256@openssh.com``,
      | ``x509v3-ecdsa-sha2-curve25519``, ``x509v3-ecdsa-sha2-nistb233``,
      | ``x509v3-ecdsa-sha2-nistb409``, ``x509v3-ecdsa-sha2-nistk163``,
      | ``x509v3-ecdsa-sha2-nistk233``, ``x509v3-ecdsa-sha2-nistk283``,
      | ``x509v3-ecdsa-sha2-nistk409``, ``x509v3-ecdsa-sha2-nistp192``,
      | ``x509v3-ecdsa-sha2-nistp224``, ``x509v3-ecdsa-sha2-nistt571``

   -  add missing KEX algorithms (#16)

      | ``curve25519-sha256``, ``curve448-sha512``, ``curve448-sha512@libssh.org``,
      | ``diffie-hellman-group-exchange-sha256@ssh.com``,
      | ``ecdh-sha2-1.2.840.10045.3.1.1``, ``ecdh-sha2-1.2.840.10045.3.1.7``,
      | ``ecdh-sha2-1.3.132.0.1``, ``ecdh-sha2-1.3.132.0.16``,
      | ``ecdh-sha2-1.3.132.0.26``, ``ecdh-sha2-1.3.132.0.27``,
      | ``ecdh-sha2-1.3.132.0.33``, ``ecdh-sha2-1.3.132.0.34``,
      | ``ecdh-sha2-1.3.132.0.35``, ``ecdh-sha2-1.3.132.0.36``,
      | ``ecdh-sha2-1.3.132.0.37``, ``ecdh-sha2-1.3.132.0.38``,
      | ``ecdh-sha2-4MHB+NBt3AlaSRQ7MnB4cg==``,
      | ``ecdh-sha2-5pPrSUQtIaTjUSt5VZNBjg==``,
      | ``ecdh-sha2-9UzNcgwTlEnSCECZa7V1mw==``,
      | ``ecdh-sha2-D3FefCjYoJ/kfXgAyLddYA==``,
      | ``ecdh-sha2-h/SsxnLCtRBh7I9ATyeB3A==``,
      | ``ecdh-sha2-m/FtSAmrV4j/Wy6RVUaK7A==``,
      | ``ecdh-sha2-mNVwCXAoS1HGmHpLvBC94w==``,
      | ``ecdh-sha2-qCbG5Cn/jjsZ7nBeR7EnOA==``,
      | ``ecdh-sha2-qcFQaMAMGhTziMT0z+Tuzw==``, ``ecdh-sha2-secp256k1``,
      | ``ecdh-sha2-VqBg4QRPjxx1EXZdV0GdWQ==``,
      | ``ecdh-sha2-wiRIU8TKjMZ418sMqlqtvQ==``,
      | ``ecdh-sha2-zD/b3hu/71952ArpUG4OjQ==``,
      | ``gss-curve25519-sha256-*``, ``gss-curve448-sha512-*``, ``gss-gex-sha1-*``,
      | ``gss-gex-sha256-*``, ``gss-group14-sha1-*``, ``gss-group14-sha256-*``,
      | ``gss-group15-sha512-*``, ``gss-group16-sha512-*``, ``gss-group17-sha512-*``,
      | ``gss-group18-sha512-*``, ``gss-group1-sha1-*``, ``gss-nistp256-sha256-*``,
      | ``gss-nistp384-sha256-*``, ``gss-nistp521-sha512-*``,
      | ``sm2kep-sha2-nistp256``

   -  add missing encryption algorithms (#16)

      | ``aes128-cfb``, ``aes192-gcm``, ``aes192-gcm@openssh.com``, ``aes256-cfb``,
      | ``aes256-gcm``, ``blowfish``, ``camellia128-cbc``,
      | ``camellia128-cbc@openssh.org``, ``camellia128-ctr``,
      | ``camellia128-ctr@openssh.org``, ``camellia192-cbc``,
      | ``camellia192-cbc@openssh.org``, ``camellia192-ctr``,
      | ``camellia192-ctr@openssh.org``, ``camellia256-cbc``,
      | ``camellia256-cbc@openssh.org``, ``camellia256-ctr``,
      | ``camellia256-ctr@openssh.org``, ``cast128-12-cbc``, ``cast128-12-cfb``,
      | ``cast128-12-ecb``, ``cast128-12-ofb``, ``chacha20-poly1305``, ``des``,
      | ``grasshopper-ctr128``, ``idea-cbc``, ``idea-ecb``, ``idea-ofb``,
      | ``kuznechik-ofb``, ``rijndael128``, ``seed-ctr@ssh.com``, ``serpent128-gcm``,
      | ``serpent128-gcm@libassh.org``, ``serpent256-gcm``,
      | ``serpent256-gcm@libassh.org``, ``sm4``, ``sm4-cbc``, ``sm4-cbc@huawei``,
      | ``sm4-ctr``, ``twofish128-gcm``, ``twofish128-gcm@libassh.org``,
      | ``twofish256-gcm``, ``twofish256-gcm@libassh.org``

   -  add missing compression algorithms (#16)

      | ``lz4@sensorsdata.cn``

-  TLS

   -  add grade for SSL cipher kinds (#18)

-------------------
0.11.2 - 2023-11-13
-------------------

Notable fixes
=============

-  Generic

   -  add missing garde for PQC algorithms

Refactor
========

-  Generic

   -  move HTTP fetcher and digest generation to common utils

-------------------
0.11.1 - 2023-11-06
-------------------

Features
========

-  Generic

   -  add missing PQC named curves (#14)

      | ``x25519/Kyber-512-r3``, ``x25519/Kyber-768-r3``

-  TLS

   -  add post-quantum safe hybrid curves (#14)

      | ``X25519_KYBER_512_R3_CLOUDFLARE``, ``X25519_KYBER_768_R3_CLOUDFLARE``

-  SSH

   -  distinguish host key algorithms use X.509 certificate from the one that use certificate chain (#12)

-------------------
0.11.0 - 2023-10-28
-------------------

Features
========

-  Generic

   -  add named attacks (#10)
   -  add well-known attack types (#10)
   -  add grade for common cryptographic algorithms (#10)
   -  add grade for public key sizes (#10)

-  DNS

   -  add grade for DNSSEC algorithms (#10)

-  TLS

   -  add grade for cipher suites (#10)
   -  add grade for named groups (#10)
   -  add grade for signature and hash algorithms (#10)

-  SSH

   -  add grade for SSH algorithms (#10)

-------------------
0.10.3 - 2023-10-12
-------------------

Notable fixes
=============

-  Generic

   -  add missing dnsrec module to the packaging (#13)

-------------------
0.10.2 - 2023-09-28
-------------------

Improvements
============

-  Generic

   -  implement value to object converter (#11)

-------------------
0.10.1 - 2023-08-29
-------------------

Features
========

-  DNS

   -  add `DNS resource record types <https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4>`__ (#8)
   -  add `DNSSEC algorithm types <https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml#dns-sec-alg-numbers-1>`__ (#8)

      | *Delete DS*, *RSA/MD5*, *Diffie-Hellman*, *DSA/SHA1*, *RSA/SHA-1*, *DSA-NSEC3-SHA1*, *RSASHA1-NSEC3-SHA1*,
        *RSA/SHA-256*, *RSA/SHA-512*, *GOST R 34.10-2001*, *ECDSA Curve P-256 with SHA-256*,
        *ECDSA Curve P-384 with SHA-384*, *Ed25519*, *Ed448*

   -  add `DNSSEC digest types <https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml>`__ (#8)

      | *SHA-1*, *SHA-256*, *GOST R 34.11-94*, *SHA-384*

-  SSH

   -  add `elliptic curve domain parameters identifier <https://www.rfc-editor.org/rfc/rfc5656.html#section-6.1>`__ (#8)

      | ``nistp256``, ``nistp384``, ``nistp521``, ``1.3.132.0.1``,
      | ``1.2.840.10045.3.1.1``, ``1.3.132.0.33``, ``1.3.132.0.26``,
      | ``1.3.132.0.27``, ``1.3.132.0.16``, ``1.3.132.0.36``, ``1.3.132.0.37``,
      | ``1.3.132.0.38``

-------------------
0.10.0 - 2023-08-03
-------------------

Features
========

-  Generic

   -  add trusted root CA certificates from notable stores (#6)

      -  `Apple <https://en.wikipedia.org/wiki/Apple_Inc.>`__
      -  `Google <https://en.wikipedia.org/wiki/Google>`__
      -  `Microsoft <https://en.wikipedia.org/wiki/Microsoft>`__
      -  `Mozilla <https://en.wikipedia.org/wiki/Mozilla>`__

   -  add TLS feature querying function for X.509 certificates (#7)

      -  Status request (OCSP must staple) extension

Notable fixes
=============

-  Generic

   -  X.509 extended validation checker

------------------
0.9.1 - 2023-06-22
------------------

Features
========

-  Generic

   -  add well-know Diffie-Hellman parameters (#3)

      | *768-bit MODP Group/Oakley Group 1*, *1024-bit MODP Group/Oakley Group 2*, *1536-bit MODP Group/Oakley Group 5*
        *2048-bit MODP Group/Oakley Group 14*, *3072-bit MODP Group/Oakley Group 15*
        *4096-bit MODP Group/Oakley Group 16*, *6144-bit MODP Group/Oakley Group 17*,
        *8192-bit MODP Group/Oakley Group 18*, *1024-bit MODP Group with 160-bit Prime Order Subgroup*,
        *2048-bit MODP Group with 224-bit Prime Order Subgroup*,
        *2048-bit MODP Group with 256-bit Prime Order Subgroup*, *2048-bit Finite Field Diffie-Hellman group*,
        *3072-bit Finite Field Diffie-Hellman group*, *4096-bit Finite Field Diffie-Hellman group*,
        *6144-bit Finite Field Diffie-Hellman group*, *8192-bit Finite Field Diffie-Hellman group*,
        Apache builtins (2.0.18, 2.1.5), HAProxy builtins (1.6), NGINX builtins (0.7.2), Postfix builtins (2.2, 3.1,
        3.6, 3.7), ProFTPD builtins (1.2.8, 1.3.2, 1.3.5, 1.3.7, 1.3.8), SOCAT builtins (1.7.3),

   -  add certificate transparency (CT) logs (#5)

      | *Akamai CT Log*, *Alpha CT Log*, *Certly.IO log*, *Cloudflare 'Nimbus2017' Log*, *Cloudflare 'Nimbus2018' Log*,
        *Cloudflare 'Nimbus2019' Log*, *Cloudflare 'Nimbus2020' Log*, *Cloudflare 'Nimbus2021' Log*,
        *Cloudflare 'Nimbus2022' Log*, *Cloudflare 'Nimbus2023' Log*, *Cloudflare 'Nimbus2024' Log*,
        *CNNIC CT log*, *DigiCert Log Server*, *DigiCert Log Server 2*, *DigiCert Nessie2018 Log*,
        *DigiCert Nessie2019 Log*, *DigiCert Nessie2020 Log*, *DigiCert Nessie2021 Log*, *DigiCert Nessie2022 Log*,
        *DigiCert Nessie2023 Log*, *DigiCert Nessie2024 Log*, *DigiCert Nessie2025 Log*, *DigiCert Yeti2018 Log*,
        *DigiCert Yeti2019 Log*, *DigiCert Yeti2020 Log*, *DigiCert Yeti2021 Log*, *DigiCert Yeti2022-2 Log*,
        *DigiCert Yeti2022 Log*, *DigiCert Yeti2023 Log*, *DigiCert Yeti2024 Log*, *DigiCert Yeti2025 Log*,
        *GDCA CT log #1*, *GDCA CT log #2*, *GDCA Log 1*, *GDCA Log 2*, *Google 'Argon2017' log*,
        *Google 'Argon2018' log*, *Google 'Argon2019' log*, *Google 'Argon2020' log*, *Google 'Argon2021' log*,
        *Google 'Argon2022' log*, *Google 'Argon2023' log*, *Google 'Argon2024' log*, *Google 'Aviator' log*,
        *Google 'Crucible' log*, *Google 'Daedalus' log*, *Google 'Icarus' log*, *Google 'Pilot' log*,
        *Google 'Rocketeer' log*, *Google 'Skydiver' log*, *Google 'Solera2018' log*, *Google 'Solera2019' log*,
        *Google 'Solera2020' log*, *Google 'Solera2021' log*, *Google 'Solera2022' log*, *Google 'Solera2023' log*,
        *Google 'Solera2024' log*, *Google 'Submariner' log*, *Google 'Testtube' log*, *Google 'Xenon2018' log*,
        *Google 'Xenon2019' log*, *Google 'Xenon2020' log*, *Google 'Xenon2021' log*, *Google 'Xenon2022' log*,
        *Google 'Xenon2023' log*, *Google 'Xenon2024' log*, *Izenpe 'Argi' log*, *Izenpe log*,
        *Let's Encrypt 'Clicky' log*, *Let's Encrypt 'Oak2019' log*, *Let's Encrypt 'Oak2020' log*,
        *Let's Encrypt 'Oak2021' log*, *Let's Encrypt 'Oak2022' log*, *Let's Encrypt 'Oak2023' log*,
        *Let's Encrypt 'Oak2024H1' log*, *Let's Encrypt 'Oak2024H2' log*, *Let's Encrypt 'Sapling 2022h2' log*,
        *Let's Encrypt 'Sapling 2023h1' log*, *Let's Encrypt 'Testflume2019' log*, *Let's Encrypt 'Testflume2020' log*,
        *Let's Encrypt 'Testflume2021' log*, *Let's Encrypt 'Testflume2022' log*, *Let's Encrypt 'Testflume2023' log*,
        *Nordu 'flimsy' log*, *Nordu 'plausible' log*, *PuChuangSiDa CT log*, *Qihoo 360 2020*, *Qihoo 360 2021*,
        *Qihoo 360 2022*, *Qihoo 360 2023*, *Qihoo 360 v1 2020*, *Qihoo 360 v1 2021*, *Qihoo 360 v1 2022*,
        *Qihoo 360 v1 2023*, *Sectigo 'Dodo' CT log*, *Sectigo 'Mammoth' CT log*, *Sectigo 'Sabre' CT log*,
        *SHECA CT log 1*, *SHECA CT log 2*, *StartCom log*, *Symantec Deneb*, *Symantec log*, *Symantec 'Sirius' log*,
        *Symantec 'Vega' log*, *Trust Asia CT2021*, *Trust Asia Log1*, *Trust Asia Log2020*, *Trust Asia Log2021*,
        *Trust Asia Log2022*, *Trust Asia Log2023*, *Trust Asia Log2024*, *Trust Asia Log2024-2*,
        *Up In The Air 'Behind the Sofa' log*, *Venafi Gen2 CT log*, *Venafi log*, *WoSign CT log #1*, *WoSign log*,
        *WoSign log 2*,

------------------
0.8.5 - 2023-04-02
------------------

Features
========

-  Generic

   -  convert Python classes of CryptoParser to JSON (#1)
   -  add Python warepper to JSON data (#1)

-  SSH

   -  add missing host key algorithms (#16)

      | ``dsa2048-sha224@libassh.org``, ``dsa2048-sha256@libassh.org``,
      | ``dsa3072-sha256@libassh.org``,
      | ``ecdsa-sha2-1.3.132.0.10-cert-v01@openssh.com``,
      | ``ecdsa-sha2-1.3.132.0.10``, ``ecdsa-sha2-nistp256-cert-v01@openssh.com``,
      | ``ecdsa-sha2-nistp256``, ``ecdsa-sha2-nistp384-cert-v01@openssh.com``,
      | ``ecdsa-sha2-nistp384``, ``ecdsa-sha2-nistp521-cert-v01@openssh.com``,
      | ``ecdsa-sha2-nistp521``, ``eddsa-e382-shake256@libassh.org``,
      | ``eddsa-e521-shake256@libassh.org``, ``pgp-sign-dss``, ``pgp-sign-rsa``,
      | ``rsa-sha2-256-cert-v01@openssh.com``, ``rsa-sha2-256``,
      | ``rsa-sha2-512-cert-v01@openssh.com``, ``rsa-sha2-512``,
      | ``sk-ecdsa-sha2-nistp256-cert-v01@openssh.com``,
      | ``sk-ecdsa-sha2-nistp256@openssh.com``,
      | ``sk-ssh-ed25519-cert-v01@openssh.com``,
      | ``sk-ssh-ed25519@openssh.com``, ``spki-sign-dss``, ``spki-sign-rsa``,
      | ``ssh-dss-cert-v00@openssh.com``, ``ssh-dss-cert-v01@openssh.com``,
      | ``ssh-dss-sha224@ssh.com``, ``ssh-dss-sha256@ssh.com``,
      | ``ssh-dss-sha384@ssh.com``, ``ssh-dss-sha512@ssh.com``,
      | ``ssh-dss``, ``ssh-ed25519-cert-v01@openssh.com``, ``ssh-ed25519``,
      | ``ssh-ed448-cert-v01@openssh.com``, ``ssh-ed448``,
      | ``ssh-rsa-cert-v00@openssh.com``, ``ssh-rsa-cert-v01@openssh.com``,
      | ``ssh-rsa-sha2-256-cert-v01@openssh.com``,
      | ``ssh-rsa-sha2-512-cert-v01@openssh.com``,
      | ``ssh-rsa-sha224@ssh.com``, ``ssh-rsa-sha256@ssh.com``,
      | ``ssh-rsa-sha384@ssh.com``, ``ssh-rsa-sha512@ssh.com``,
      | ``ssh-rsa``, ``x509v3-ecdsa-sha2-1.3.132.0.10``,
      | ``x509v3-ecdsa-sha2-nistp256``, ``x509v3-ecdsa-sha2-nistp384``,
      | ``x509v3-ecdsa-sha2-nistp521``, ``x509v3-rsa2048-sha256``,
      | ``x509v3-sign-dss-sha1``, ``x509v3-sign-dss-sha224@ssh.com``,
      | ``x509v3-sign-dss-sha256@ssh.com``, ``x509v3-sign-dss-sha384@ssh.com``,
      | ``x509v3-sign-dss-sha512@ssh.com``, ``x509v3-sign-dss``,
      | ``x509v3-sign-rsa-sha1``, ``x509v3-sign-rsa-sha224@ssh.com``,
      | ``x509v3-sign-rsa-sha256@ssh.com``, ``x509v3-sign-rsa-sha384@ssh.com``,
      | ``x509v3-sign-rsa-sha512@ssh.com``, ``x509v3-sign-rsa``, ``x509v3-ssh-dss``,
      | ``x509v3-ssh-ed25519``, ``x509v3-ssh-ed448``, ``x509v3-ssh-rsa``

   -  add missing KEX algorithms (#16)

      | ``diffie-hellman-group1-sha1``, ``diffie-hellman-group1-sha256``,
      | ``diffie-hellman-group1-sha1-win7@microsoft.com``,
      | ``diffie-hellman-group14-sha1``,
      | ``diffie-hellman-group14-sha1-win7@microsoft.com``,
      | ``diffie-hellman-group14-sha224@ssh.com``,
      | ``diffie-hellman-group14-sha256``,
      | ``diffie-hellman-group14-sha256@ssh.com``,
      | ``diffie-hellman-group15-sha256``,
      | ``diffie-hellman-group15-sha256@ssh.com``,
      | ``diffie-hellman-group15-sha384@ssh.com``,
      | ``diffie-hellman-group15-sha512``,
      | ``diffie-hellman-group16-sha256``,
      | ``diffie-hellman-group16-sha384@ssh.com``,
      | ``diffie-hellman-group16-sha512``,
      | ``diffie-hellman-group16-sha512@ssh.com``,
      | ``diffie-hellman-group17-sha512``,
      | ``diffie-hellman-group18-sha512``,
      | ``diffie-hellman-group18-sha512@ssh.com``,
      | ``diffie-hellman-group-exchange-sha1``,
      | ``diffie-hellman-group-exchange-sha256``,
      | ``diffie-hellman-group-exchange-sha256-win7@microsoft.com``,
      | ``diffie-hellman-group-exchange-sha512``,
      | ``diffie-hellman-group-exchange-sha224@ssh.com``,
      | ``diffie-hellman-group-exchange-sha384@ssh.com``,
      | ``diffie-hellman-group-exchange-sha512@ssh.com``,
      | ``ecdh-sha2-1.3.132.0.10``, ``ecdh-sha2-brainpoolp256r1@genua.de``,
      | ``ecdh-sha2-brainpoolp384r1@genua.de``,
      | ``ecdh-sha2-brainpoolp521r1@genua.de``,
      | ``ecdh-sha2-curve25519``, ``ecdh-sha2-nistb233``, ``ecdh-sha2-nistb409``,
      | ``ecdh-sha2-nistk163``, ``ecdh-sha2-nistk233``, ``ecdh-sha2-nistk283``,
      | ``ecdh-sha2-nistk409``, ``ecdh-sha2-nistp192``, ``ecdh-sha2-nistp224``,
      | ``ecdh-sha2-nistp256``, ``ecdh-sha2-nistp256-win7@microsoft.com``,
      | ``ecdh-sha2-nistp384``, ``ecdh-sha2-nistp384-win7@microsoft.com``,
      | ``ecdh-sha2-nistp521``, ``ecdh-sha2-nistp521-win7@microsoft.com``,
      | ``ecdh-sha2-nistt571``, ``ecmqv-sha2``, ``curve25519-sha256``,
      | ``curve25519-sha256@libssh.org``, ``curve448-sha512``,
      | ``kexguess2@matt.ucc.asn.au``, ``m383-sha384@libassh.org``,
      | ``m511-sha512@libassh.org``, ``rsa1024-sha1``, ``rsa2048-sha256``,
      | ``sntrup4591761x25519-sha512@tinyssh.org``,
      | ``sntrup761x25519-sha512@openssh.com``

   -  add missing encryption algorithms (#1)

      | ``3des-cbc``, ``3des-cfb``, ``3des-ctr``, ``3des-ecb``, ``3des-ofb``,
      | ``acss@openssh.org``, ``aes128-cbc``, ``aes128-ctr``,
      | ``aes128-gcm@openssh.com``, ``aes128-gcm``, ``aes192-cbc``, ``aes192-ctr``,
      | ``aes256-cbc``, ``aes256-ctr``, ``aes256-gcm@openssh.com``, ``arcfour128``,
      | ``arcfour256``, ``arcfour``, ``blowfish-cbc``, ``blowfish-cfb``,
      | ``blowfish-ctr``, ``blowfish-ecb``, ``blowfish-ofb``,
      | ``cast128-12-cbc@ssh.com``, ``cast128-12-cfb@ssh.com``,
      | ``cast128-12-ecb@ssh.com``, ``cast128-12-ofb@ssh.com``,
      | ``cast128-cbc``, ``cast128-cfb``, ``cast128-ctr``, ``cast128-ecb``,
      | ``cast128-ofb``, ``cast256-cbc``, ``chacha20-poly1305@openssh.com``,
      | ``crypticore128@ssh.com``, ``des-cbc@ssh.com``, ``des-cbc``, ``des-cfb``,
      | ``des-ctr``, ``des-ecb``, ``des-ofb``, ``gost89-cnt``, ``gost89``,
      | ``grasshopper-cbc``, ``grasshopper-ctr``, ``idea-cfb``, ``idea-ctr``,
      | ``none``, ``rc2-cbc@ssh.com``, ``rc2-cbc``, ``rc2-ctr``,
      | ``rijndael-cbc@lysator.liu.se``, ``rijndael-cbc@ssh.com``,
      | ``rijndael128-cbc``, ``rijndael192-cbc``, ``rijndael256-cbc``,
      | ``seed-cbc@ssh.com``, ``serpent128-cbc``, ``serpent128-ctr``,
      | ``serpent192-cbc``, ``serpent192-ctr``, ``serpent256-cbc``,
      | ``serpent256-ctr``, ``twofish-cbc``, ``twofish-cfb``, ``twofish-ctr``,
      | ``twofish-ecb``, ``twofish-ofb``, ``twofish128-cbc``, ``twofish128-ctr``,
      | ``twofish192-cbc``, ``twofish192-ctr``, ``twofish256-cbc``,
      | ``twofish256-ctr``

   -  add missing compression algorithms (#1)

      | ``none``, ``zlib@openssh.com``, ``zlib``

-  TLS

   -  add capabilities of Chromium, Firefox and Opera browsers

      -  `Chromium <https://en.wikipedia.org/wiki/Chromium_(web_browser)>`__
      -  `Firefox <https://en.wikipedia.org/wiki/Firefox>`__
      -  `Opera <https://en.wikipedia.org/wiki/Opera_(web_browser)>`__
