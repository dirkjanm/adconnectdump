using System.Security.Cryptography;
using DPAPI;

namespace Shwmae.Ngc.Keys.Crypto
{
    public interface KeyCrypto
    {
        byte[] Sign(byte[] data, HashAlgorithmName alg);
        byte[] Decrypt(byte[] data);
        byte[] Export();
    }
}
