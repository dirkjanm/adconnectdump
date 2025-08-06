using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using DPAPI;
using NtApiDotNet;
using NtApiDotNet.Win32;

namespace Shwmae {
    public static class Utils {

        public class RequireStruct<T> where T : struct { }
        public class RequireClass<T> where T : class { }

        public static string Base64Url(byte[] data) {
            char[] padding = { '=' };
            return Convert.ToBase64String(data).TrimEnd(padding).Replace('+', '-').Replace('/', '_');
        }

        public static byte[] Base64Url(string data) {
            string incoming = data.Replace('_', '/').Replace('-', '+');
            switch (data.Length % 4) {
                case 2: incoming += "=="; break;
                case 3: incoming += "="; break;
            }
            return Convert.FromBase64String(incoming);            
        }

        public static string Hex(this byte[] ba, bool upper = false) {
            StringBuilder hex = new StringBuilder(ba.Length * 2);

            foreach (byte b in ba)
                if (upper)
                    hex.AppendFormat($"{b:X2}");
                else
                    hex.AppendFormat($"{b:x2}");

            return hex.ToString();
        }

        public static byte[] FromHex(this string hex) {
            byte[] raw = new byte[hex.Length / 2];
            for (int i = 0; i < raw.Length; i++) {
                raw[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return raw;
        }

        public static string Repeat(this string text, uint n) {
            return string.Concat(Enumerable.Repeat(text, (int)n));        
        }

        public static byte[] ToBytes<T>(this T obj, RequireStruct<T> ignore = null) where T : struct {
            return ToNative(obj);
        } 

        public static byte[] ToBytes<T>(this T obj, RequireClass<T> ignore = null) where T : class {
            return ToNative(obj);
        }

        public static T ToStructure<T>(this IntPtr ptr)  {
            return Marshal.PtrToStructure<T>(ptr);
        }

        static byte[] ToNative(object obj) {
            var result = new byte[Marshal.SizeOf(obj)];
            GCHandle h = GCHandle.Alloc(result, GCHandleType.Pinned);
            Marshal.StructureToPtr(obj, h.AddrOfPinnedObject(), false);
            h.Free();
            return result;
        }

        public static byte[] AesDecrypt(byte[] encData, byte[] key, byte[] iv, CipherMode cipherMode = CipherMode.CBC) {
            using (var aes = new AesManaged()) {
                aes.IV = iv;
                aes.Key = key;
                aes.Mode = cipherMode;

                using (MemoryStream ms = new MemoryStream()) {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write)) {
                        cs.Write(encData, 0, encData.Length);
                        cs.FlushFinalBlock();
                        return ms.ToArray();
                    }
                }
            }
        }

        static NtToken DuplicateProcessToken(NtProcess process) {

            var result = process.OpenToken(TokenAccessRights.Duplicate | TokenAccessRights.GenericRead, false);

            if (result.IsSuccess)
                return result.Result.DuplicateToken(SecurityImpersonationLevel.Impersonation);
            else {
                Console.WriteLine($"[!] Failed to open process token {process.Name} ({process.ProcessId}) ");
                return null;
            }
        }

        static NtToken GetSystem(string user) {

            NtToken result;

            if (!NtToken.EnableEffectivePrivilege(TokenPrivilegeValue.SeDebugPrivilege) || !NtToken.EnableEffectivePrivilege(TokenPrivilegeValue.SeImpersonatePrivilege)) {
                throw new UnauthorizedAccessException("[!] Failed to get privileges when trying to gain SYSTEM");
            }

            var systemToken = DuplicateProcessToken(NtProcess.GetProcesses(ProcessAccessRights.DupHandle | ProcessAccessRights.QueryInformation).First(p => p.Name.Equals("winlogon.exe", StringComparison.OrdinalIgnoreCase)));

            if (user != "SYSTEM") {
                using (var ctx = systemToken.Impersonate()) {
                    if (user == "LocalService") {
                        result = NtProcess.GetProcesses(ProcessAccessRights.AllAccess)
                            .Where(p => p.OpenToken().User.Sid == KnownSids.LocalService)
                            .Select(p => DuplicateProcessToken(p))
                            .Where(t => t != null)
                            .First();
                    } else if (user == "NetworkService") {
                        result = NtProcess.GetProcesses(ProcessAccessRights.AllAccess)
                            .Where(p => p.OpenToken().User.Sid == KnownSids.NetworkService)
                            .Select(p => DuplicateProcessToken(p))
                            .Where(t => t != null)
                            .First();
                    }
                    else if (user == "ADSync")
                    {
                        if (ServiceUtils.GetService("ADSync").Status == ServiceStatus.Stopped)
                        {
                            ServiceUtils.StartService("ADSync", new string[] { });
                        }

                        result = NtProcess.GetProcesses(ProcessAccessRights.AllAccess)
                            .Where(p => p.OpenToken().User.Name == "NT SERVICE\\ADSync")
                            .Select(p => p.OpenToken())
                            .First().DuplicateToken(SecurityImpersonationLevel.Impersonation);
                    }
                    else if (user == "Ngc") {

                        if(ServiceUtils.GetService("NgcCtnrSvc").Status == ServiceStatus.Stopped) {
                            ServiceUtils.StartService("NgcCtnrSvc", new string[] { });
                        }

                        result = NtProcess.GetProcesses(ProcessAccessRights.AllAccess)
                            .Select(p => p.OpenToken())
                            .Where(t => t.User.Sid == KnownSids.LocalService && t.Groups.Any(g => g.Name == "NT SERVICE\\NgcCtnrSvc"))
                            .First().DuplicateToken(SecurityImpersonationLevel.Impersonation);
                    } else {
                        throw new ArgumentException("Only SYSTEM, LocalService or NetworkService can be used");
                    }
                }
            } else {
                result = systemToken;
            }

            return result;
        }

        public static ThreadImpersonationContext Impersonate(string impersonate) {

            if (impersonate == null)
                throw new ArgumentNullException(nameof(impersonate));

            NtToken impersonateToken;
            string[] systemAccounts = new string[] { "SYSTEM", "LocalService", "NetworkService", "Ngc" };

            //We need to load assemblies that are triggered under impersonation because
            //often the DLL's might be in a location where the impersonated user doesn't
            //have read access
            //Assembly.Load("JWT");
            //Assembly.Load("System.Text.Json");
            //Assembly.Load("System.Memory");
            //Assembly.Load("Microsoft.Bcl.AsyncInterfaces");
            //Assembly.Load("System.Threading.Tasks.Extensions");
            //Assembly.Load("System.Text.Encodings.Web");
            //Assembly.Load("System.Buffers");
            //Assembly.Load("System.Collections.Immutable");
            //Assembly.Load("Dahomey.Cbor");
            Assembly.Load("Newtonsoft.Json");
            //Assembly.Load("NLog");

            impersonateToken = GetSystem(impersonate);
            var impersonationContext = impersonateToken.Impersonate();
            return impersonationContext;
        }
    }
}
