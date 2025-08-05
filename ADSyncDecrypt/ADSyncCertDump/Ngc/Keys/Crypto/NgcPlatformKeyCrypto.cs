using System;
using System.Security.Cryptography;
using DPAPI;

namespace Shwmae.Ngc.Keys.Crypto
{
    public class NgcPlatformKeyCrypto : KeyCrypto
    {

        string keyId;

        public NgcPlatformKeyCrypto(string keyId)
        {
            this.keyId = keyId;
        }

        public byte[] Decrypt(byte[] data)
        {
            throw new NotImplementedException();
        }
        public byte[] Export()
        {
            throw new NotImplementedException();
        }
        public byte[] Sign(byte[] data, HashAlgorithmName alg)
        {
            var cngKey = CngKey.Open(keyId, new CngProvider("Microsoft Platform Crypto Provider"), CngKeyOpenOptions.Silent);

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
}
