using System;
using System.Data.SqlClient;
using System.Text;
using System.IO;

namespace ADSyncQuery
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("1: Use " + Environment.MachineName);
            Console.WriteLine("2: Use LocalDB (Default)");
            Console.WriteLine("3: Specify a server name");
            Console.Write("Enter your choice (1, 2, or 3): ");
            int choice = Convert.ToInt32(Console.ReadLine());

            string dataSource = "";
            switch (choice)
            {
                case 1:
                    dataSource = Environment.MachineName;  // HOSTNAME
                    break;
                case 2:
                    dataSource = "(LocalDB)\\MSSQLLocalDB"; // LocalDB
                    break;
                case 3:
                    Console.Write("Enter the server name: ");
                    dataSource = Console.ReadLine(); // custom server name
                    break;
                default:
                    Console.WriteLine("Invalid choice. Exiting.");
                    return;
            }

            Console.Write("Enter the full path to the file (or just the filename if it's in the current directory): ");
            string filePath = Console.ReadLine();
            if (!Path.IsPathRooted(filePath))
            {
                filePath = Path.Combine(Directory.GetCurrentDirectory(), filePath);
            }

            string connstring = string.Format("Data Source={0};AttachDbFilename=\"{1}\";Integrated Security=True;Connect Timeout=30", dataSource, filePath);
            Console.WriteLine("Opening database {0}", filePath);
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