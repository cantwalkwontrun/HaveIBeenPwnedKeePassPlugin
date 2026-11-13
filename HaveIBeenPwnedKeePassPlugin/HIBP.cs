using System;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Security.Authentication;
using System.Threading;
using System.Threading.Tasks;

namespace HaveIBeenPwnedPlugin
{
    internal sealed class HIBP : IDisposable
    {
        private const string HIBP_RangeApiUrl = "https://api.pwnedpasswords.com/range/";
        private readonly HttpClient _httpClient;

        public HIBP() : this(new HttpClient(new HttpClientHandler
        {
            // Keep TLS policy local to this plugin instead of changing KeePass globally.
            SslProtocols = SslProtocols.Tls12 | (SslProtocols)12288,
            AllowAutoRedirect = false
        }))
        {
        }

        internal HIBP(HttpClient httpClient)
        {
            _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
            _httpClient.Timeout = TimeSpan.FromSeconds(30);
            _httpClient.MaxResponseContentBufferSize = 2 * 1024 * 1024;
            _httpClient.DefaultRequestHeaders.Add("User-Agent", $"KeePass Plugin {nameof(HaveIBeenPwnedPlugin)}");
            _httpClient.DefaultRequestHeaders.Add("Add-Padding", "true");
        }

        public async Task<(bool isBreached, long breachCount)> CheckRangeAsync(string sha1Prefix, string sha1Suffix,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            if (!IsHex(sha1Prefix, 5)) throw new ArgumentException("Expected five SHA-1 hexadecimal characters.", nameof(sha1Prefix));
            if (!IsHex(sha1Suffix, 35)) throw new ArgumentException("Expected 35 SHA-1 hexadecimal characters.", nameof(sha1Suffix));
            using (var response = await _httpClient.GetAsync(HIBP_RangeApiUrl + sha1Prefix, cancellationToken).ConfigureAwait(false))
            {
                response.EnsureSuccessStatusCode();
                return ParseRange(await response.Content.ReadAsStringAsync().ConfigureAwait(false), sha1Suffix);
            }
        }

        internal static (bool isBreached, long breachCount) ParseRange(string response, string sha1Suffix)
        {
            bool foundRow = false;
            long breachCount = 0;
            using (var reader = new StringReader(response))
            {
                string row;
                while ((row = reader.ReadLine()) != null)
                {
                    if (row.Length == 0) continue;
                    // Invalid responses must never clear a breach tag.
                    if (row.Length < 37 || row[35] != ':' || !IsHex(row.Substring(0, 35), 35) ||
                        !long.TryParse(row.Substring(36), NumberStyles.None, CultureInfo.InvariantCulture, out long count))
                    {
                        throw new HttpRequestException("Invalid HIBP range response.");
                    }

                    foundRow = true;
                    if (string.Equals(row.Substring(0, 35), sha1Suffix, StringComparison.OrdinalIgnoreCase))
                    {
                        breachCount = Math.Max(breachCount, count);
                    }
                }
            }

            if (!foundRow) throw new HttpRequestException("Empty HIBP range response.");
            return (breachCount > 0, breachCount);
        }

        private static bool IsHex(string value, int length)
        {
            if (value == null || value.Length != length) return false;
            foreach (char c in value)
            {
                if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))) return false;
            }
            return true;
        }

        public Task<(bool isBreached, long breachCount)> CheckRangeAsync((string sha1Prefix, string sha1Suffix) sha1Values,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            return CheckRangeAsync(sha1Values.sha1Prefix, sha1Values.sha1Suffix, cancellationToken);
        }

        public void Dispose() => _httpClient.Dispose();
    }
}
