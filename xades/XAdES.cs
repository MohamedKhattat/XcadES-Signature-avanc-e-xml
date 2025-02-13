using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;

namespace xades
{
    class XAdES
    {
        protected X509Certificate2 x509Certificate2;
        protected RSA rsa;

        public XAdES(X509Certificate2 x509Certificate2)
        {
            this.x509Certificate2 = x509Certificate2 ?? throw new ArgumentNullException(nameof(x509Certificate2));
            this.rsa = x509Certificate2.GetRSAPrivateKey();

            if (this.rsa == null)
            {
                throw new InvalidOperationException("Private key is not an RSA key or cannot be converted to RSA.");
            }
        }

        public XAdES(string sCertificate)
        {
            if (string.IsNullOrWhiteSpace(sCertificate))
                throw new ArgumentException("Certificate name cannot be null or empty.", nameof(sCertificate));

            using (X509Store myCertsStore = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                myCertsStore.Open(OpenFlags.ReadOnly);
                foreach (X509Certificate2 cert in myCertsStore.Certificates)
                {
                    if (cert.Subject.Contains(sCertificate))
                    {
                        this.x509Certificate2 = cert;
                        break;
                    }
                }
            }

            if (x509Certificate2 == null)
            {
                throw new Exception("Certificate " + sCertificate + " not found.");
            }

            this.rsa = x509Certificate2.GetRSAPrivateKey() ?? throw new InvalidOperationException("Private key is not an RSA key.");
        }

        public string Sign(string sFolder, string sFileName, bool boEnveloped)
        {
            if (string.IsNullOrWhiteSpace(sFolder))
                throw new ArgumentException("Folder path cannot be null or empty.", nameof(sFolder));
            if (string.IsNullOrWhiteSpace(sFileName))
                throw new ArgumentException("File name cannot be null or empty.", nameof(sFileName));

            byte[] fileXML = File.ReadAllBytes(Path.Combine(sFolder, sFileName));
            return Sign(fileXML, boEnveloped);
        }

        public string Sign(string sXMLDocument, bool boEnveloped)
        {
            if (string.IsNullOrWhiteSpace(sXMLDocument))
                throw new ArgumentException("XML document cannot be null or empty.", nameof(sXMLDocument));

            byte[] fileXML = Encoding.Default.GetBytes(sXMLDocument);
            return Sign(fileXML, boEnveloped);
        }

        public byte[] C14NTransform(byte[] fileXML)
        {
            using (Stream stream = new MemoryStream(fileXML))
            {
                XmlDsigC14NTransform xmlDsigC14NTransform = new XmlDsigC14NTransform(true);
                xmlDsigC14NTransform.LoadInput(stream);

                using (MemoryStream outputStream = (MemoryStream)xmlDsigC14NTransform.GetOutput(typeof(Stream)))
                {
                    return outputStream.ToArray();
                }
            }
        }

        public string Sign(byte[] fileXML, bool boEnveloped)
        {
            byte[] fileC14NXML = C14NTransform(fileXML);

            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashFileXml = sha256.ComputeHash(fileC14NXML);
                string sB64_Hash = Convert.ToBase64String(hashFileXml, Base64FormattingOptions.None);
                string sB64_Cert = Convert.ToBase64String(x509Certificate2.GetRawCertData(), Base64FormattingOptions.None);

                string sKeyInfo = $"<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" Id=\"idKeyInfo\">" +
                                  $"<X509Data><X509Certificate>{sB64_Cert}</X509Certificate></X509Data></KeyInfo>";

                byte[] abKeyInfo = Encoding.Default.GetBytes(sKeyInfo);
                byte[] hashKeyInfo = sha256.ComputeHash(abKeyInfo);
                string sB64_HKey = Convert.ToBase64String(hashKeyInfo, Base64FormattingOptions.None);

                string sTimestamp = GetTimestamp();
                string sSignedProperties = $"<SignedProperties xmlns=\"http://uri.etsi.org/01903/v1.3.2#\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" Id=\"idSignedProperties\">" +
                                           $"<SignedSignatureProperties><SigningTime>{sTimestamp}</SigningTime></SignedSignatureProperties></SignedProperties>";

                byte[] abSignedProperties = Encoding.Default.GetBytes(sSignedProperties);
                byte[] hashSignedProperties = sha256.ComputeHash(abSignedProperties);
                string sB64_HSPr = Convert.ToBase64String(hashSignedProperties, Base64FormattingOptions.None);

                string sIdRef_1 = "xmldsig-" + Guid.NewGuid().ToString("D");
                string sRef_1 = $"<Reference Id=\"{sIdRef_1}\" URI=\"\"><Transforms>" +
                                $"<Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></Transform>" +
                                $"<Transform Algorithm=\"http://www.w3.org/2006/12/xml-c14n11#WithComments\"></Transform></Transforms>" +
                                $"<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></DigestMethod>" +
                                $"<DigestValue>{sB64_Hash}</DigestValue></Reference>";

                string sIdRef_2 = "xmldsig-" + Guid.NewGuid().ToString("D");
                string sRef_2 = $"<Reference Id=\"{sIdRef_2}\" URI=\"#idKeyInfo\"><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></DigestMethod>" +
                                $"<DigestValue>{sB64_HKey}</DigestValue></Reference>";

                string sIdRef_3 = "xmldsig-" + Guid.NewGuid().ToString("D");
                string sRef_3 = $"<Reference Id=\"{sIdRef_3}\" Type=\"http://uri.etsi.org/01903#SignedProperties\" URI=\"#idSignedProperties\">" +
                                $"<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></DigestMethod>" +
                                $"<DigestValue>{sB64_HSPr}</DigestValue></Reference>";

                string sSignedInfo = $"<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" +
                                     $"<CanonicalizationMethod Algorithm=\"http://www.w3.org/2006/12/xml-c14n11#WithComments\"></CanonicalizationMethod>" +
                                     $"<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"></SignatureMethod>" +
                                     $"{sRef_1}{sRef_2}{sRef_3}</SignedInfo>";

                byte[] abSignedInfo = Encoding.Default.GetBytes(sSignedInfo);
                byte[] hashSignedInfo = sha256.ComputeHash(abSignedInfo);

                byte[] signature = rsa.SignHash(hashSignedInfo, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); // Utilisation de RSA
                string sB64_Sign = Convert.ToBase64String(signature, Base64FormattingOptions.None);

                StringBuilder sXMLSignature = new StringBuilder();
                string sIdSignature = "xmldsig-" + Guid.NewGuid().ToString("D");

                sXMLSignature.Append($"<Signature Id=\"{sIdSignature}\" xmlns=\"http://www.w3.org/2000/09/xmldsig#\">");
                sXMLSignature.Append("<SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2006/12/xml-c14n11#WithComments\"></CanonicalizationMethod>");
                sXMLSignature.Append("<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"></SignatureMethod>");
                sXMLSignature.Append($"{sRef_1}{sRef_2}{sRef_3}</SignedInfo>");
                sXMLSignature.Append($"<SignatureValue>{sB64_Sign}</SignatureValue>");
                sXMLSignature.Append("<KeyInfo Id=\"idKeyInfo\"><X509Data><X509Certificate>");
                sXMLSignature.Append($"{sB64_Cert}</X509Certificate></X509Data></KeyInfo>");
                sXMLSignature.Append("<Object Id=\"idObject\"><QualifyingProperties Target=\"#");
                sXMLSignature.Append($"{sIdSignature}\" xmlns=\"http://uri.etsi.org/01903/v1.3.2#\"><SignedProperties Id=\"idSignedProperties\"");
                sXMLSignature.Append(" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><SignedSignatureProperties><SigningTime>");
                sXMLSignature.Append($"{sTimestamp}</SigningTime></SignedSignatureProperties></SignedProperties></QualifyingProperties></Object></Signature>");

                if (!boEnveloped)
                {
                    return sXMLSignature.ToString();
                }

                string sOutput = Encoding.Default.GetString(fileXML);
                string sSignatureCodeTag = "</signatureCode>";
                int iSignatureCode = sOutput.IndexOf(sSignatureCodeTag);
                if (iSignatureCode > 0)
                {
                    int iStartSignature = iSignatureCode + sSignatureCodeTag.Length;
                    return sOutput.Substring(0, iStartSignature) + sXMLSignature + sOutput.Substring(iStartSignature);
                }
                int iLastTag = sOutput.LastIndexOf("</");
                return sOutput.Substring(0, iLastTag) + sXMLSignature + sOutput.Substring(iLastTag);
            }
        }

        private string GetTimestamp()
        {
            DateTime dtCurrent = DateTime.UtcNow;
            return dtCurrent.ToString("yyyy-MM-ddTHH:mm:ssZ");
        }
    }
}
