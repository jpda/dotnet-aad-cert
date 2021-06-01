using System;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using static System.Environment;
using System.Security.Cryptography.X509Certificates;

namespace dotnet_client_cert
{
    class Program
    {
        static X509Store GetCertificateStore()
        {
            var s = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            if (OSVersion.Platform == PlatformID.Unix)
            {
                s.Open(OpenFlags.ReadWrite);
                var certData = System.IO.File.ReadAllBytes("/etc/ssl/private/jpda-brutus-app.pfx");
                s.Add(new X509Certificate2(certData, "watermelon"));
            }
            return s;
        }

        static async Task Main(string[] args)
        {
            var store = GetCertificateStore();
            store.Open(OpenFlags.ReadOnly);
            Console.WriteLine($"{store.Certificates.Count} certificates found in store");
            foreach (var a in store.Certificates)
            {
                Console.WriteLine($"{a.SubjectName.Name}");
            }

            var results = store.Certificates.Find(X509FindType.FindBySubjectName, "jpda-brutus-cert-app", false);
            var cert = results[0];

            var msal = ConfidentialClientApplicationBuilder
                .Create("b9c4fe08-c461-412c-8358-64c02d111287")
                .WithAuthority("https://login.microsoftonline.com/jpda.onmicrosoft.com")
                .WithCertificate(cert)
                .Build()
            ;

            AuthenticationResult token;

            try
            {
                token = await msal.AcquireTokenForClient(new[] { "https://graph.microsoft.com/.default" }).ExecuteAsync();
                Console.WriteLine("Got a token!");
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return;
            }

            var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token.AccessToken);
            var graphResult = await httpClient.GetAsync("https://graph.microsoft.com/v1.0/users?$top=5");
            if (graphResult.IsSuccessStatusCode)
            {
                var doc = System.Text.Json.JsonDocument.Parse(await graphResult.Content.ReadAsStringAsync());
                var a = doc.RootElement.GetProperty("value").EnumerateArray();
                foreach (var p in a)
                {
                    Console.WriteLine($"hello {p.GetProperty("displayName").GetString()} ({p.GetProperty("userPrincipalName").GetString()})");
                }

            }

            Console.WriteLine("all finished. enter to exit");
            Console.ReadLine();
        }
    }
}