using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace WebApiAuthentication.Client
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Press enter to start...");
            Console.ReadLine();

            try
            {
                var credentials = new NetworkCredential("test", "test");
                var handler = new HttpClientHandler { Credentials = credentials };

                using (var client = new HttpClient(handler))
                {
                    client.DefaultRequestHeaders.Add("clientid", "world-direct");

                    HttpResponseMessage response = client.GetAsync("http://localhost:59310/api/test").Result;
                    response.EnsureSuccessStatusCode();
                    Console.WriteLine("Everything ok");
                }

            } catch(Exception ex)
            {
                Console.WriteLine(ex);
            }

            Console.WriteLine("Press enter to quit");
            Console.ReadLine();
        }
    }
}
