namespace CertChecker
{
    using System.Net.Security;
    using System.Net.Sockets;
    using System.Security.Cryptography.X509Certificates;

    internal class Program
    {
        private const string DomainsFileName = "domains.txt";
        private const string LogFileName = "cs-out.log";
        private const int CheckIntervalMinutes = 1;

        private static async Task Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Please provide the working directory as the first argument.");
                return;
            }

            string workingDirectory = args[0];
            if (!Directory.Exists(workingDirectory))
            {
                Console.WriteLine($"The directory '{workingDirectory}' does not exist. Please provide a valid path.");
                return;
            }

            string domainsFilePath = Path.Combine(workingDirectory, DomainsFileName);
            string logFilePath = Path.Combine(workingDirectory, LogFileName);

            while (true)
            {
                var domainList = await ReadDomainsAsync(domainsFilePath);

                foreach (string domain in domainList)
                {
                    await CheckCertificateAsync(domain, logFilePath);
                }

                await Task.Delay(TimeSpan.FromMinutes(CheckIntervalMinutes));
            }
        }

        private static async Task<List<string>> ReadDomainsAsync(string filePath)
        {
            var domainList = new List<string>();

            using (var reader = File.OpenText(filePath))
            {
                string line;
                while ((line = await reader.ReadLineAsync()) != null)
                {
                    if (line.StartsWith("#") || string.IsNullOrWhiteSpace(line))
                        continue;

                    string domain = new Uri(line).Host;
                    domainList.Add(domain);
                }
            }

            return domainList;
        }

        private static async Task CheckCertificateAsync(string domain, string logFilePath)
        {
            try
            {
                var tcpClient = new TcpClient(domain, 443);
                using (var sslStream = new SslStream(tcpClient.GetStream(), false, ValidateServerCertificate))
                {
                    await sslStream.AuthenticateAsClientAsync(domain);
                }
            }
            catch (Exception ex)
            {
                await LogErrorAsync(domain, ex.Message, logFilePath);
            }
        }

        private static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            Console.WriteLine($"Certificate error: {sslPolicyErrors}");
            return false;
        }

        private static async Task LogErrorAsync(string domain, string errorMessage, string logFilePath)
        {
            using (var logFile = new StreamWriter(logFilePath, true))
            {
                string logEntry = $"[{DateTime.UtcNow}] Domain: {domain}, Error: {errorMessage}";
                Console.WriteLine(logEntry);
                await logFile.WriteLineAsync(logEntry);
            }
        }
    }
}
