using System;
using System.Net;

namespace Fluxzy.Utils
{
    public static class AuthorityUtility
    {
        private static readonly char[] Separators = { ':', '/' };

        /// <summary>
        /// Parse an authority, accepted separator are ':' and '/'.
        /// </summary>
        /// <param name="rawValue"></param>
        /// <param name="host"></param>
        /// <param name="port"></param>
        /// <returns></returns>
        public static bool TryParse(string rawValue, out string? host, out int port)
        {
            host = null; 
            port = 0;

            foreach (var separator in Separators) {
                var lastColumn = rawValue.AsSpan().LastIndexOf(separator);

                if (lastColumn == -1)
                    continue;

                var hostName = rawValue.AsSpan()[..lastColumn].TrimStart();
                var rawPort = rawValue.AsSpan()[(lastColumn + 1)..].TrimEnd();

                if (hostName.IsEmpty) {
                    continue; 
                }

                if (!int.TryParse(rawPort, out port))
                    continue;

                if (port < 0 || port > 65535) {
                    port = 0;
                    return false; 
                }

                host = hostName.ToString();

                return true;
            }

            return false;
        }

        /// <summary>
        ///  Parse an authority, accepted separator are ':' and '/'. Authority must me a valid IPv4 or IPv6 address.
        /// </summary>
        /// <param name="rawValue"></param>
        /// <param name="ip"></param>
        /// <param name="port"></param>
        /// <returns></returns>
        public static bool TryParseIp(string rawValue, out IPAddress? ip, out int port)
        {
            ip = null; 
            port = 0;

            var result = TryParse(rawValue, out var rawHost, out port);

            if (!result)
                return false;

            if (IPAddress.TryParse(rawHost!, out var parsedIp)) {
                ip = parsedIp;
                return true;
            }

            ip = null;
            port = 0;

            return false;
        }
    }
}