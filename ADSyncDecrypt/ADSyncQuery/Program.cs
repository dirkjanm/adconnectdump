using System;

using System.Data.SqlClient;
using System.Text;

namespace ADSyncQuery
{
    class Program
    {
        static void Main(string[] args)
        {
            string connstring = string.Format("Data Source=(LocalDB)\\MSSQLLocalDB;AttachDbFilename=\"{0}\";Integrated Security=True;Connect Timeout=30", args[0]);
            Console.WriteLine("Opening database {0}", args[0]);
            using (SqlConnection conn = new SqlConnection(connstring))
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

            }
        }
    }
}
