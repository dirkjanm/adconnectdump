using SharpDPAPI;
using Shwmae;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;

namespace DPAPI {
    public struct DPAPI_BLOB {
        public uint Version;
        public Guid GuidCredential;
        public uint MasterKeyVersion;
        public Guid GuidMasterKey;
        public uint Flags;
        public string Description;
        public int CryptoAlgo;
        public int CryptoAlgoLen;
        public byte[] Salt;
        public byte[] HMACKey;
        public int HashAlgo;
        public int HashAlgoLen;
        public byte[] HMAC;
        public byte[] Data;
        public byte[] Signature;
        public byte[] Blob;

        public static DPAPI_BLOB Parse(byte[] blob) {            
            var result = Parse(new BinaryReader(new MemoryStream(blob)));
            result.Blob = blob.Skip(20).Take(blob.Length - (20 + result.Signature.Length + 4)).ToArray();
            return result;
        }

        public static DPAPI_BLOB Parse(BinaryReader br) {
            return new DPAPI_BLOB() {
                Version = br.ReadUInt32(),
                GuidCredential = new Guid(br.ReadBytes(16)),
                MasterKeyVersion = br.ReadUInt32(),
                GuidMasterKey = new Guid(br.ReadBytes(16)),
                Flags = br.ReadUInt32(),
                Description = Encoding.Unicode.GetString(br.ReadBytes(br.ReadInt32())),
                CryptoAlgo = br.ReadInt32(),
                CryptoAlgoLen = br.ReadInt32(),
                Salt = br.ReadBytes(br.ReadInt32()),
                HMACKey = br.ReadBytes(br.ReadInt32()),
                HashAlgo = br.ReadInt32(),
                HashAlgoLen = br.ReadInt32(),
                HMAC = br.ReadBytes(br.ReadInt32()),
                Data = br.ReadBytes(br.ReadInt32()),
                Signature = br.ReadBytes(br.ReadInt32())
            };
        }
        public byte[] DecryptCu(byte[] entropy = null)
        {
            try
            {
                byte[] decryptedData = ProtectedData.Unprotect(
                    Blob,
                    entropy,
                    DataProtectionScope.CurrentUser // or LocalMachine
                );

                return decryptedData;
            }
            catch (CryptographicException e)
            {
                Console.WriteLine("DPAPI Decryption failed: " + e.Message);
                return null;
            }
        }
        public byte[] Decrypt(byte[] masterKey, byte[] entropy = null) {

            switch (HashAlgo) {

                case 32782: {

                        var derivedKeyBytes = SharpDPAPI.Crypto.DeriveKey(masterKey, Salt, HashAlgo, entropy);
                        var finalKeyBytes = new byte[CryptoAlgoLen / 8];
                        Array.Copy(derivedKeyBytes, finalKeyBytes, CryptoAlgoLen / 8);

                        if (entropy != null) {
                            // for CNG, we need a different padding mode
                            return SharpDPAPI.Crypto.DecryptBlob(Data, finalKeyBytes, CryptoAlgo, PaddingMode.PKCS7);
                        } else {
                            return SharpDPAPI.Crypto.DecryptBlob(Data, finalKeyBytes, CryptoAlgo);
                        }
                    }

                // 32772 == CALG_SHA1
                case 32772: {
                        var algCryptLen = 192; //3DES rounding
                        var derivedKeyBytes = SharpDPAPI.Crypto.DeriveKey(masterKey, Salt, HashAlgo, entropy);
                        var finalKeyBytes = new byte[algCryptLen / 8];
                        Array.Copy(derivedKeyBytes, finalKeyBytes, algCryptLen / 8);
                        return SharpDPAPI.Crypto.DecryptBlob(Data, finalKeyBytes, CryptoAlgo);
                    }

                default:
                    throw new NotImplementedException($"Hash algorithm currently not supported: {HashAlgo}");
            }
        }
    }
}
