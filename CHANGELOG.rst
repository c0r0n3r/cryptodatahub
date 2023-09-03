Changelog
=========

0.10.1 - 2023-08-29
-------------------

-  DNS

   -  add `DNS resource record types <https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4>`__ (#8)
   -  add `DNSSEC algorithm types <https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml#dns-sec-alg-numbers-1>`__ (#8)
   -  add `DNSSEC digest types <https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml>`__ (#8)

-  SSH

   -  add `elliptic curve domain parameters identifier <https://www.rfc-editor.org/rfc/rfc5656.html#section-6.1>`__ (#8)

0.10.0 - 2023-08-03
-------------------

Features
~~~~~~~~

-  Generic

   -  add trusted root CA certificates from notable stores (#6)

      -  `Apple <https://en.wikipedia.org/wiki/Apple_Inc.>`__
      -  `Google <https://en.wikipedia.org/wiki/Google>`__
      -  `Microsoft <https://en.wikipedia.org/wiki/Microsoft>`__
      -  `Mozilla <https://en.wikipedia.org/wiki/Mozilla>`__

   -  add TLS feature querying function for X.509 certificates (#7)

      -  Status request (OCSP must staple) extension

Notable fixes
~~~~~~~~~~~~~

-  Generic

   -  X.509 extended validation checker

0.9.1 - 2023-06-22
------------------

Features
~~~~~~~~

-  Generic

   -  add well-know Diffie-Hellman parameters (#3)
   -  add certificate transparency (CT) logs (#5)

0.8.5 - 2023-04-02
------------------

Features
~~~~~~~~

-  Generic

   -  convert Python classes of CryptoParser to JSON (#1)
   -  add Python warepper to JSON data (#1)

-  TLS

   -  add capabilities of Chromium, Firefox and Opera browsers

      -  `Chromium <https://en.wikipedia.org/wiki/Chromium_(web_browser)>`__
      -  `Firefox <https://en.wikipedia.org/wiki/Firefox>`__
      -  `Opera <https://en.wikipedia.org/wiki/Opera_(web_browser)>`__
