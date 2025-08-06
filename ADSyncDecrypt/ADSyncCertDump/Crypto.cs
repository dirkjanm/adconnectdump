using System.Runtime.InteropServices;
using System;
using System.Security.Cryptography;
using System.Text;
using System.Reflection;
using Microsoft.Win32.SafeHandles;
using System.IO;
using System.Linq;
using PBKDF2;
using NtApiDotNet;
using NtApiDotNet.Utilities.Security;
using DPAPI;
using Shwmae.Ngc;

namespace Shwmae {
    public class Crypto {

        class SafeNCryptDescriptorHandle : SafeHandleZeroOrMinusOneIsInvalid {

            public SafeNCryptDescriptorHandle(IntPtr preexistingHandle, bool ownsHandle) : base(ownsHandle) {
                SetHandle(preexistingHandle);
            }

            public SafeNCryptDescriptorHandle() : base(true) {
            }

            [DllImport("NCrypt.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            static extern uint NCryptCloseProtectionDescriptor(IntPtr hDescriptor);
     
            protected override bool ReleaseHandle() {
                if (!IsInvalid) {
                    uint result = NCryptCloseProtectionDescriptor(handle);
                    handle = IntPtr.Zero; 
                    return result == 0;
                }
                return true;                
            }
    
        }
     
      
       
        static string ReadNcgFileString(string path) {
            var fileData = File.ReadAllBytes(path);
            return  Encoding.Unicode.GetString(fileData.Take(fileData.Length - 2).ToArray());
        }     

     
        public static byte[] DeriveKeyFromPassword(string sid, string password, bool domainUser) {

            var encodedSidNull = Encoding.Unicode.GetBytes(sid + "\0");
            var encodedSid = encodedSidNull.Take(encodedSidNull.Length - 2).ToArray();
            byte[] hmacData = null;

            if (!domainUser) {

                using (var sha1 = new SHA1Managed()) {
                    hmacData = sha1.ComputeHash(Encoding.Unicode.GetBytes(password));
                }

            } else {

                var ntHash = MD4.CalculateHash(Encoding.Unicode.GetBytes(password));

                using (var hmac256 = new HMACSHA256()) {
                    hmacData = new Pbkdf2(hmac256, new Pbkdf2(hmac256, ntHash, encodedSid, 10000)
                        .GetBytes(32, "sha256"), encodedSid, 1)
                        .GetBytes(16, "sha256");
                }
            }

            using (var hmac = new HMACSHA1(hmacData)) {
                return hmac.ComputeHash(encodedSidNull);
            }
        }

    }
}