using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace xades
{
    class Program
    {
        static void Main(string[] args)
        {
            /*string certPath = "C:\\Users\\Arab Soft\\Documents\\GitHub\\CEF\\xades\\certificate.pfx";
            string certPassword = "123456"; */
            string certPath = "C:\\Users\\Arab Soft\\Documents\\GitHub\\CEF\\xades\\SilvestrisGiorgio.pfx";
            string certPassword = "motdepasse123"; 

            try
            {
                // Vérifiez si le fichier de certificat existe
                if (!File.Exists(certPath))
                {
                    throw new FileNotFoundException($"Le fichier de certificat est introuvable : {certPath}");
                }

                Console.WriteLine("🔹 Chargement du certificat...");

                X509Certificate2 cert = new X509Certificate2(certPath, certPassword,
                    X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);

                Console.WriteLine("✅ Certificat chargé avec succès !");
                Console.WriteLine($"📌 Sujet : {cert.Subject}");
                Console.WriteLine($"🔐 Clé privée présente : {cert.HasPrivateKey}");
                Console.WriteLine($"🔑 Algorithme de signature : {cert.SignatureAlgorithm.FriendlyName}");

                if (!cert.HasPrivateKey)
                {
                    Console.Error.WriteLine("❌ Le certificat ne contient pas de clé privée !");
                    return;
                }

                // Vérification si la clé privée est utilisable avec RSA
                var rsa = cert.GetRSAPrivateKey();
                if (rsa == null)
                {
                    Console.Error.WriteLine("❌ La clé privée n'est pas RSA ! Peut-être ECDSA ?");
                    return;
                }

                Console.WriteLine("🔹 Test de signature avec XAdES...");

                string sXMLDocument = "<x c=\"3\" a=\"1\" b=\"2\"></x>";
                Console.WriteLine($"📜 XML original : {sXMLDocument}");

                XAdES xades = new XAdES(cert);
                string signedXml = xades.Sign(sXMLDocument, true);

                Console.WriteLine($"✍ XML signé : {signedXml}");

                string signedXmlFilePath = "signed_xml.xml";
                File.WriteAllText(signedXmlFilePath, signedXml);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"❌ Erreur : {ex.Message}");
            }

            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }
    }
}
