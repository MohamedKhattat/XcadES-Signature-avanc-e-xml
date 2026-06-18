# XAdES — Advanced XML Signature

> XML Advanced Electronic Signatures (XAdES) for fiscal e-invoicing.

![C#](https://img.shields.io/badge/C%23-239120?style=for-the-badge&logo=c-sharp&logoColor=white)
![.NET Framework](https://img.shields.io/badge/.NET%20Framework%204.8-512BD4?style=for-the-badge&logo=dotnet&logoColor=white)
![XML](https://img.shields.io/badge/XML-005FAD?style=for-the-badge&logo=xml&logoColor=white)
![Cryptography](https://img.shields.io/badge/Cryptography-RSA%20%2F%20SHA--256-FF6F00?style=for-the-badge&logo=letsencrypt&logoColor=white)
![X.509](https://img.shields.io/badge/X.509-Certificate-2C3E50?style=for-the-badge&logo=keycdn&logoColor=white)

---

## Overview

**XAdES** (XML Advanced Electronic Signatures, ETSI TS 101 903) extends the
W3C XML Digital Signature standard (XML-DSig) with the additional qualifying
properties — such as the signing time and the signer's certificate — that a
signature needs to carry legal value in a fiscal / regulatory context. It is
the signature format used by electronic-invoicing platforms (for example
Tunisia's **El Fatoura / TEIF**) to seal an invoice before it is submitted to
the tax authority.

This repository is a compact **C# / .NET Framework** reference implementation
that builds a XAdES signature **by hand** — composing the `SignedInfo`,
`Reference`, `KeyInfo`, and ETSI `SignedProperties` / `QualifyingProperties`
XML by string assembly, hashing each part with SHA-256, and signing with an
RSA private key loaded from an X.509 certificate. Building the signature
explicitly (rather than through a black-box library) makes every digest,
canonicalization choice and namespace visible — which is exactly what is
needed when a signature has to match a tax platform's precise expected layout.

It also includes a companion module that produces a **WS-Security signed SOAP
envelope**, the transport wrapper typically used to call an e-invoicing web
service.

## Features

Implemented in the source as it stands:

- **XAdES enveloped & detached signatures** (`XAdES.cs`)
  - Canonicalization of the input document via `XmlDsigC14NTransform` (C14N).
  - **SHA-256** digests over the document, the `KeyInfo`, and the
    `SignedProperties`.
  - **RSA / SHA-256** signature (`rsa-sha256`, PKCS#1 padding) over the
    `SignedInfo`.
  - Three `Reference` elements: the document itself (with an
    *enveloped-signature* transform), the `KeyInfo`, and the
    ETSI `SignedProperties`.
  - **ETSI XAdES qualifying properties** (`http://uri.etsi.org/01903/v1.3.2#`)
    carrying the `SigningTime` (UTC timestamp).
  - **Two signing modes** — return the `<Signature>` block alone (detached),
    or inject it into the source document (enveloped). The enveloped mode
    inserts the signature after a `</signatureCode>` marker when present, or
    before the document's closing tag otherwise.
- **Certificate loading** — from a PFX file *or* by subject lookup in the
  Windows certificate store (`StoreName.My`, `CurrentUser`); the X.509
  certificate is embedded base64 in the `X509Data` of the signature.
- **WS-Security SOAP envelope** (`WSSecurity.cs`)
  - Builds a signed `soapenv:Envelope` with a `wsse:BinarySecurityToken`,
    a `wsu:Timestamp` (created / expires), and a `ds:Signature`.
  - **Exclusive XML canonicalization** (`xml-exc-c14n#`) with explicit
    `InclusiveNamespaces` prefix lists.
  - **RSA / SHA-1** signature over the timestamp reference, with a
    `SecurityTokenReference` pointing back to the X.509 token
    (OASIS WSS 1.0 / X.509 Token Profile).
- **Console demo** (`Program.cs`) — loads a certificate, reports its subject /
  private-key / signature-algorithm details, signs a sample XML document, and
  writes the result to `signed_xml.xml`.

## Tech Stack

| Layer | Technology |
|-------|------------|
| Language | C# |
| Framework | .NET Framework 4.8 |
| Output | Console application (`.exe`) |
| Cryptography | `System.Security.Cryptography` — RSA, SHA-256, SHA-1 |
| XML / signing | `System.Security.Cryptography.Xml` — C14N transforms, XML-DSig |
| Certificates | `System.Security.Cryptography.X509Certificates` — X.509 / PFX / cert store |
| Build | MSBuild / Visual Studio solution (`xades.sln`) |
| CI | GitHub Actions (.NET desktop workflow) |

## Project Structure

```
XcadES-Signature-avanc-e-xml/
├── xades.sln                  # Visual Studio solution
├── xades/
│   ├── Program.cs             # Console entry point / demo
│   ├── XAdES.cs               # XAdES signature builder (C14N, SHA-256, RSA-SHA256, ETSI properties)
│   ├── WSSecurity.cs          # WS-Security signed SOAP envelope (exc-c14n, RSA-SHA1, timestamp)
│   ├── Properties/
│   │   └── AssemblyInfo.cs
│   ├── app.config
│   └── xades.csproj           # .NET Framework 4.8 project
└── .github/
    └── workflows/
        └── dotnet-desktop.yml # CI build workflow
```

## Getting Started

### Prerequisites

- Windows with the **.NET Framework 4.8** developer pack
- **Visual Studio 2017+** or the MSBuild command-line tools
- A valid **X.509 signing certificate** with an exportable **RSA private key**
  (a `.pfx` file, or a certificate installed in the current-user store)

### Build

```bash
# From the repository root
msbuild xades.sln /p:Configuration=Release
```

or open `xades.sln` in Visual Studio and build.

### Run

The console demo in `Program.cs` expects a certificate path and password.
**Do not hard-code credentials** — supply your own certificate via
configuration, an environment variable, or the Windows certificate store, then
run the produced `xades.exe`. The demo signs a sample XML string and writes the
signed output to `signed_xml.xml`.

Programmatic use of the signer:

```csharp
// Load a certificate (PFX or from the cert store) that has an RSA private key
var cert = new X509Certificate2(/* your certificate + password */);

var xades = new XAdES(cert);

// boEnveloped = true  -> signature injected into the document
// boEnveloped = false -> returns the <Signature> block alone
string signedXml = xades.Sign("<x c=\"3\" a=\"1\" b=\"2\"></x>", boEnveloped: true);
```

## Notes

- This is a focused **reference / proof-of-concept** implementation. It builds
  the signature XML by explicit string assembly so that every digest,
  namespace and canonicalization step is transparent and tunable to a target
  fiscal platform's expected layout — it is not packaged as a general-purpose
  signing library.
- **Security:** never commit certificates, private keys, PFX passwords or PINs.
  The sample paths and any inline credentials in the demo are placeholders for
  illustration only; load real secrets from a secure store or configuration at
  runtime.
- The two modules use **different signature algorithms by design**: XAdES uses
  **SHA-256** (`rsa-sha256`), while the WS-Security envelope uses **SHA-1**
  (`rsa-sha1`) as required by the OASIS WS-Security / X.509 Token Profile it
  targets.
- The signer relies on an **RSA** private key; certificates whose key is ECDSA
  (or that have no private key) are rejected at load time.

---
<p align="center">Built by <b>Mohamed Habib Khattat</b> — <a href="https://github.com/MohamedKhattat">GitHub</a> · <a href="https://www.linkedin.com/in/mohamed-habib-khattat-2b206a173">LinkedIn</a></p>
