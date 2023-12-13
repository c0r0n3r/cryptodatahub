=========
Changelog
=========

-------------------
0.12.1 - 2023-12-13
-------------------

Improvements
============

-  SSH

   -  add missing compression algorithms (#16)
   -  add missing encryption algorithms (#16)
   -  add missing host key algorithms (#16)
   -  add missing KEX algorithms (#16)

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

-  TLS

   -  add post-quantum safe hybrid curves (#14)

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
   -  add `DNSSEC digest types <https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml>`__ (#8)

-  SSH

   -  add `elliptic curve domain parameters identifier <https://www.rfc-editor.org/rfc/rfc5656.html#section-6.1>`__ (#8)

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
   -  add certificate transparency (CT) logs (#5)

------------------
0.8.5 - 2023-04-02
------------------

Features
========

-  Generic

   -  convert Python classes of CryptoParser to JSON (#1)
   -  add Python warepper to JSON data (#1)

-  TLS

   -  add capabilities of Chromium, Firefox and Opera browsers

      -  `Chromium <https://en.wikipedia.org/wiki/Chromium_(web_browser)>`__
      -  `Firefox <https://en.wikipedia.org/wiki/Firefox>`__
      -  `Opera <https://en.wikipedia.org/wiki/Opera_(web_browser)>`__
