--------
Features
--------

Protocol-independent
====================

Algorithms
----------

-  `public key <https://en.wikipedia.org/wiki/Public-key_cryptography>`__
-  `digital signature <https://en.wikipedia.org/wiki/Digital_signature>`__
-  `key exchange <https://en.wikipedia.org/wiki/Key_exchange>`__
-  `block cipher <https://en.wikipedia.org/wiki/Block_cipher>`__
-  `stream cipher <https://en.wikipedia.org/wiki/Stream_cipher>`__
-  `cryptographic hash <https://en.wikipedia.org/wiki/Cryptographic_hash_function>`__
-  `elliptic-curve <https://en.wikipedia.org/wiki/Elliptic-curve_cryptography>`__
-  `message authentication code <https://en.wikipedia.org/wiki/Message_authentication_code>`__

Parameters
----------

-  Diffie-Hellman (finite field)

   -  defined by standard

      -  `RFC 2539 <https://www.rfc-editor.org/rfc/rfc2539.html#appendix-A>`__ (a.k.a MODP, Oakley Group)
      -  `RFC 3526 <https://www.rfc-editor.org/rfc/rfc3526.html>`__ (a.k.a MODP for IKE)
      -  `RFC 5114 <https://www.rfc-editor.org/rfc/rfc5114.html>`__
      -  `RFC 7919 <https://www.rfc-editor.org/rfc/rfc7919.html#appendix-A>`__ (a.k.a FFDH)

   -  software built-in

      -  `Apache HTTP Server <https://en.wikipedia.org/wiki/Apache_HTTP_Server>`__
      -  `HAProxy <https://en.wikipedia.org/wiki/HAProxy>`__
      -  `Postfix <https://en.wikipedia.org/wiki/Postfix_(software)>`__
      -  `ProFTPD <https://en.wikipedia.org/wiki/ProFTPD>`__
      -  SOcket CAT (socat)

Stores
------

-  Trusted root CA certificate trust stores

   -  `Apple <https://en.wikipedia.org/wiki/Apple_Inc.>`__
   -  `Google <https://en.wikipedia.org/wiki/Google>`__
   -  `Microsoft <https://en.wikipedia.org/wiki/Microsoft>`__
   -  `Mozilla <https://en.wikipedia.org/wiki/Mozilla>`__

-  `Certificate Transaprency <https://certificate.transparency.dev>`__ (CT)
   `Logs <https://certificate.transparency.dev/logs>`__

   -  Cloudflare
   -  DigiCert
   -  Google
   -  Let's Encrypt
   -  Sectigo
   -  TrustAsia
   -  ...

Protocol-dependent
==================

Attributes
----------

-  Secure Socket Layer (SSL)

   -  `cipher kind <https://datatracker.ietf.org/doc/html/draft-hickman-netscape-ssl-00>`__

-  Transport Layer Security (TLS)

   -  `application-layer protocol name <https://www.rfc-editor.org/rfc/rfc7301>`__
   -  `certificate compression algorithm <https://www.rfc-editor.org/rfc/rfc8879.html>`__
   -  `cipher suite <https://www.rfc-editor.org/rfc/rfc5246#appendix-D.3>`__
   -  `compression method <https://www.rfc-editor.org/rfc/rfc3749>`__
   -  `elliptic-curve point format <https://www.rfc-editor.org/rfc/rfc4492.html#section-5.1.2>`__
   -  `extension type <https://www.rfc-editor.org/rfc/rfc3546>`__
   -  `fallback SCSV <https://www.rfc-editor.org/rfc/rfc7507.html>`__
   -  `hash and signature algorithm <https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.1.4.1>`__
   -  `named curve <https://www.rfc-editor.org/rfc/rfc4492.html#section-5.1.1>`__
   -  `next protocol name <https://datatracker.ietf.org/doc/html/draft-agl-tls-nextprotoneg-04>`__
   -  `psk key exchange mode <https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.9>`__
   -  `renegotiation indication <https://www.rfc-editor.org/rfc/rfc5746>`__
   -  `token binding paramater <https://www.rfc-editor.org/rfc/rfc8471.html>`__


-  Secure Shell (SSH)

   -  `key exchange <https://www.rfc-editor.org/rfc/rfc4253#section-6.5>`__
   -  `public key <https://www.rfc-editor.org/rfc/rfc4253#section-6.6>`__
   -  `encryption <https://www.rfc-editor.org/rfc/rfc4253#section-6.3>`__
   -  `message authentication code <https://www.rfc-editor.org/rfc/rfc4253#section-6.4>`__
   -  `compression <https://www.rfc-editor.org/rfc/rfc4253#section-6.2>`__
   -  `elliptic curve domain parameter identifier <https://www.rfc-editor.org/rfc/rfc5656.html#section-6.1>`__

-  Domain Name System

   -  `DNS resource record (RR) types <https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4>`__
   -  `DNSSEC algorithm types <https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml#dns-sec-alg-numbers-1>`__
   -  `DNSSEC digest types <https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml>`__

Client Capabilities
-------------------

-  Transport Layer Security (TLS)

   -  Hypertext Transfer Protocol Secure (HTTPS)

      -  `Chromium <https://en.wikipedia.org/wiki/Chromium_(web_browser)>`__
      -  `Firefox <https://en.wikipedia.org/wiki/Firefox>`__
      -  `Opera <https://en.wikipedia.org/wiki/Opera_(web_browser)>`__
