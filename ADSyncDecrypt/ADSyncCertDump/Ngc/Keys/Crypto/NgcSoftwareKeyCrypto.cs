using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using DPAPI;

namespace Shwmae.Ngc.Keys.Crypto
{
    public class NgcSoftwareKeyCrypto : KeyCrypto
    {
        public int Rounds { get; private set; }
        public byte[] Salt { get; private set; }
        public CNGKeyBlob KeyBlob { get; private set; }

        public NgcSoftwareKeyCrypto(string path){
            KeyBlob = CNGKeyBlob.Parse(path);
        }

        public NgcSoftwareKeyCrypto(CNGKeyBlob keyBlob) {
            KeyBlob = keyBlob;
        }

        public void DecryptPrivatePropertiesCu()
        {


            var privatePropertiesBlob = ProtectedData.Unprotect(
                    KeyBlob.PrivatePropertiesBytes,
                    Encoding.UTF8.GetBytes("6jnkd5J3ZdQDtrsu\0"),
                    DataProtectionScope.CurrentUser // or LocalMachine
                );

            if (privatePropertiesBlob.Length == 0)
            {
                throw new ArgumentException("keyBlob does not contain private key properties");
            }

            var privateProperties = CNGProperty.Parse(new BinaryReader(new MemoryStream(privatePropertiesBlob)), (uint)privatePropertiesBlob.Length);

        }


        byte[] DecryptKeyCu()
        {

            DecryptPrivatePropertiesCu();

            byte[] entropy = Encoding.UTF8.GetBytes("xT5rZW5qVVbrvpuA\0");

            var privatePropertiesBlob = ProtectedData.Unprotect(
                    KeyBlob.PrivateKeyBytes,
                    entropy,
                    DataProtectionScope.CurrentUser // or LocalMachine
                );
            return privatePropertiesBlob;
        }

        CngKey LoadKey()
        {
            return CngKey.Import(DecryptKeyCu(), CngKeyBlobFormat.GenericPrivateBlob, CngProvider.MicrosoftSoftwareKeyStorageProvider);
        }

        public byte[] Sign(byte[] data, HashAlgorithmName alg)
        {

            using (var cngKey = LoadKey())
            {

                if (cngKey.Algorithm == CngAlgorithm.Rsa)
                {
                    var rsa = new RSACng(cngKey);
                    return rsa.SignData(data, alg, RSASignaturePadding.Pkcs1);
                }
                else if (cngKey.Algorithm == CngAlgorithm.ECDsa)
                {
                    var ecdsa = new ECDsaCng(cngKey);
                    return ecdsa.SignData(data, alg);
                }
                else
                {
                    throw new NotImplementedException($"Algorithm {cngKey.Algorithm} not currently supported");
                }
            }
        }
        public byte[] DecryptAuto(byte[] data)
        {

            using (var cngKey = LoadKey())
            {
                if (cngKey.Algorithm == CngAlgorithm.Rsa)
                {
                    var rsa = new RSACng(cngKey);
                    return rsa.Decrypt(data, RSAEncryptionPadding.Pkcs1);
                }
                else if (cngKey.Algorithm == CngAlgorithm.ECDsa)
                {
                    throw new CryptographicException($"Key type {cngKey.Algorithm} doesn't support decryption");
                }
                else
                {
                    throw new NotImplementedException($"Algorithm {cngKey.Algorithm} not currently supported");
                }
            }
        }

        public byte[] Decrypt(byte[] data)
        {

            using (var cngKey = LoadKey())
            {
                if (cngKey.Algorithm == CngAlgorithm.Rsa)
                {
                    var rsa = new RSACng(cngKey);
                    return rsa.Decrypt(data, RSAEncryptionPadding.Pkcs1);
                }
                else if (cngKey.Algorithm == CngAlgorithm.ECDsa)
                {
                    throw new CryptographicException($"Key type {cngKey.Algorithm} doesn't support decryption");
                }
                else
                {
                    throw new NotImplementedException($"Algorithm {cngKey.Algorithm} not currently supported");
                }
            }
        }
        public byte[] Export()
        {

            var cngKey = DecryptKeyCu();

            var keyParams = new CngKeyCreationParameters
            {
                ExportPolicy = CngExportPolicies.AllowPlaintextExport,
                KeyCreationOptions = CngKeyCreationOptions.None,
                Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider
            };
            keyParams.Parameters.Add(new CngProperty(CngKeyBlobFormat.GenericPrivateBlob.Format, cngKey, CngPropertyOptions.None));
            var key = CngKey.Create(CngAlgorithm.Rsa, null, keyParams);
            return key.Export(CngKeyBlobFormat.Pkcs8PrivateBlob);
        }
    }
}
