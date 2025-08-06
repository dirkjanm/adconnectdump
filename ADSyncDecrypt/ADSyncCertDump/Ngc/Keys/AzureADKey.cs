using System;
using System.Security.Cryptography;
using System.Linq;
using Shwmae.Ngc.Keys.Crypto;
using DPAPI;
using System.Text;
using Microsoft.Win32;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Collections.Generic;
using Newtonsoft.Json;
using System.Runtime.InteropServices;

namespace Shwmae.Ngc.Keys {


    [StructLayout (LayoutKind.Sequential)]
    public struct BCRYPT_OAEP_PADDING_INFO {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string AlgId;
        public IntPtr Label;
        public uint LabelSize;
    }  
    
    public class ADSyncKey : NgcKey {

        public ADSyncKey(KeyCrypto key) : base() => crypto = key;

        public string CreateAssertion(string kid, string client_id, string tenant)
        {
            string x5t = Base64UrlEncode(kid.FromHex());
            var header = new Dictionary<string, object>
            {
                { "typ", "JWT" },
                { "alg", "RS256" },
                { "x5t", x5t }
            };

            string encheader = Base64UrlEncode(JsonConvert.SerializeObject(header));

            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            long expiry = now + 24 * 60 * 60 * 365;
            expiry = now + 300;

            var claims = new Dictionary<string, object>
            {
                { "iss", client_id },
                { "aud", $"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token" },
                { "iat", now },
                { "nbf", now },
                { "exp", expiry },
                { "jti", Guid.NewGuid().ToString() },
                { "sub", client_id }
            };

            string encbody = Base64UrlEncode(JsonConvert.SerializeObject(claims));

            string jwt = $"{encheader}.{encbody}";

            // Hash JWT
            //SHA256 sha256 = SHA256.Create();
            //byte[] hash = sha256.ComputeHash();

            byte[] signature = crypto.Sign(Encoding.UTF8.GetBytes(jwt), HashAlgorithmName.SHA256);


            string sig = Base64UrlEncode(signature);
            string assertion = $"{jwt}.{sig}";

            return assertion;
        }

        private static string Base64UrlEncode(string input)
            => Base64UrlEncode(Encoding.UTF8.GetBytes(input));

        private static string Base64UrlEncode(byte[] input)
        {
            return Convert.ToBase64String(input)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }

    }
}
