namespace CertChecker
{
    using System.Net.Security;
    using System.Net.Sockets;
    using System.Threading.Tasks;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;

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
            try
            {
                await LogErrorToPapertrailAsync(errorMessage);
            }
            catch(Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        private static async Task LogErrorToPapertrailAsync(string errorMessage)
        {
            var papertrailDestination = Environment.GetEnvironmentVariable("PAPERTRAIL");

            if (string.IsNullOrEmpty(papertrailDestination))
            {
                return;
            }

            var destinationParts = papertrailDestination.Split(':');
            if (destinationParts.Length != 2)
            {
                Console.WriteLine("Invalid PAPERTRAIL environment variable format. Expected format: <host>:<port>");
                return;
            }

            var host = destinationParts[0];
            if (!int.TryParse(destinationParts[1], out int port))
            {
                Console.WriteLine("Invalid PAPERTRAIL environment variable format. Port should be a number.");
                return;
            }

            await SendLogAsync(host, port, errorMessage);
        }

        private static async Task SendLogAsync(string host, int port, string message)
        {
            using (var udpClient = new UdpClient())
            {
                try
                {
                    var logMessage = Encoding.ASCII.GetBytes(message);
                    await udpClient.SendAsync(logMessage, logMessage.Length, host, port);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error sending log to Papertrail: {ex.Message}");
                }
            }
        }
    }
}
