using System;
using static System.Environment;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace dotnet_client_cert
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            await CreateHostBuilder(args).Build().RunAsync();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureServices((hostContext, services) =>
                {
                    services.Configure<CertificateCredentialConfiguration>(hostContext.Configuration.GetSection("AzureAd:Credential"));
                    services.Configure<AzureAdConfiguration>(hostContext.Configuration.GetSection("AzureAd"));
                    services.AddSingleton<IMsalCredential, XPlatCertificateCredential>();
                    services.AddSingleton<MsalBuilder>();
                    services.AddHostedService<GraphReaderHostedService>();
                });
    }

    public class GraphReaderHostedService : IHostedService
    {
        private readonly ILogger _logger;
        private readonly MsalBuilder _msalBuilder;

        public GraphReaderHostedService(ILogger<GraphReaderHostedService> logger, MsalBuilder builder)
        {
            _logger = logger;
            _msalBuilder = builder;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            var msal = _msalBuilder.Build();
            AuthenticationResult token;

            try
            {
                token = await msal.AcquireTokenForClient(new[] { "https://graph.microsoft.com/.default" }).ExecuteAsync(cancellationToken);
                _logger.LogInformation("Got a token!");
                await CallGraph(token.AccessToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(100, ex, ex.Message);
                return;
            }

            _logger.LogInformation("all finished. enter to exit");
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        private async Task CallGraph(string token)
        {
            var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            var graphResult = await httpClient.GetAsync("https://graph.microsoft.com/v1.0/users?$top=5");
            if (graphResult.IsSuccessStatusCode)
            {
                var doc = System.Text.Json.JsonDocument.Parse(await graphResult.Content.ReadAsStringAsync());
                var a = doc.RootElement.GetProperty("value").EnumerateArray();
                foreach (var p in a)
                {
                    _logger.LogInformation($"hello {p.GetProperty("displayName").GetString()} ({p.GetProperty("userPrincipalName").GetString()})");
                }
            }
        }
    }

    public class MsalBuilder
    {
        private readonly AzureAdConfiguration _config;
        private readonly IMsalCredential _credential;

        public MsalBuilder(IOptions<AzureAdConfiguration> config, IMsalCredential credential)
        {
            _config = config.Value;
            _credential = credential;
        }

        public IConfidentialClientApplication Build()
        {
            var msal = ConfidentialClientApplicationBuilder
                .Create(_config.ClientId)
                .WithAuthority(_config.Authority)
                .WithCredential(_credential)
                .Build()
            ;
            return msal;
        }
    }

    public static class MsalBuilderExt
    {
        public static ConfidentialClientApplicationBuilder WithCredential(this ConfidentialClientApplicationBuilder builder, IMsalCredential credential)
        {
            if (credential.GetType() == typeof(XPlatCertificateCredential))
            {
                var cert = credential.GetCredential<X509Certificate2>();
                builder.WithCertificate(cert);
                return builder;
            }
            builder.WithClientSecret(credential.GetCredential<string>());
            return builder;
        }
    }

    public interface IMsalCredential
    {
        T GetCredential<T>() where T : class;
    }

    public class XPlatCertificateCredential : IMsalCredential
    {
        private readonly CertificateCredentialConfiguration _config;
        private readonly ILogger _logger;
        public XPlatCertificateCredential(IOptions<CertificateCredentialConfiguration> config, ILogger<XPlatCertificateCredential> logger)
        {
            _config = config.Value;
            _logger = logger;
        }

        private X509Store GetCertificateStore()
        {
            var s = new X509Store(Enum.Parse<StoreName>(_config.Store.Name), Enum.Parse<StoreLocation>(_config.Store.Scope));
            if (OSVersion.Platform == PlatformID.Unix)
            {
                s.Open(OpenFlags.ReadWrite);
                var certData = System.IO.File.ReadAllBytes(_config.File.Path);
                s.Add(new X509Certificate2(certData, _config.File.Password));
            }
            return s;
        }

        public T GetCredential<T>() where T : class
        {
            var store = GetCertificateStore();
            store.Open(OpenFlags.ReadOnly);
            foreach (var a in store.Certificates)
            {
                _logger.LogDebug($"{a.SubjectName.Name}");
            }

            var results = store.Certificates.Find(X509FindType.FindBySubjectName, _config.SubjectName, false);
            var cert = results[0];
            return cert as T;
        }
    }

    public class AzureAdConfiguration
    {
        public string ClientId { get; set; }
        public string Authority { get; set; }
        public CertificateCredentialConfiguration Credential { get; set; }
    }

    public class CertificateCredentialConfiguration
    {
        public string SubjectName { get; set; }
        public CertificateFileCredentialConfiguration File { get; set; }
        public CertificateStoreCredentialConfiguration Store { get; set; }
    }

    public class CertificateFileCredentialConfiguration
    {
        public string Path { get; set; }
        public string Password { get; set; }
    }

    public class CertificateStoreCredentialConfiguration
    {
        public string Name { get; set; }
        public string Scope { get; set; }
    }
}