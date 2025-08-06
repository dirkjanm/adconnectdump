using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DPAPI;
using Shwmae.Ngc.Keys.Crypto;

namespace Shwmae.Ngc.Keys {


    public class NgcKey
    {
        public string Name { get; private set; }
        public string KeyId { get; private set; }
        public string Provider { get; private set; }
        public string KeyPath { get; private set; }
        public string KeyType { get; private set; }
        public string User { get; private set; }
        public X509Certificate2 Certificate { get; private set; }
        public bool IsSoftware { get; private set; }

        protected KeyCrypto crypto;


        public NgcKey()
        {

        }

        NgcKey(string user, string provider, string id)
        {
            User = user;
            Provider = provider;
            Name = id;
        }

        public static IEnumerable<NgcKey> GetNgcKeys()
        {
            return new CngProvider("Microsoft Passport Key Storage Provider")
                .EnumerateKeys(CngKeyOpenOptions.None)
                .Select(k => new NgcKey(null, "Microsoft Passport Key Storage Provider", k.pszName));
        }

        public byte[] Sign(byte[] data, HashAlgorithmName alg)
        {
            return crypto.Sign(data, alg);
        }

        public byte[] Decrypt(byte[] data)
        {
            return crypto.Decrypt(data);
        }

        public byte[] Dump() {
            
            if (!IsSoftware) {
                throw new InvalidOperationException("Cannot dump TPM backed key");
            }

            return ((NgcSoftwareKeyCrypto)crypto).Export();
        }

        public override string ToString()
        {
            return $"{Name} ({Provider})";
        }
    }
}
