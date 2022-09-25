// Copyright � 2022 Haga Rakotoharivelo

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Fluxzy.Misc.Streams;
using Fluxzy.Readers;
using Fluxzy.Tests.Cli.Scaffolding;
using Fluxzy.Tests.Tools;
using Fluxzy.Tests.Utils;
using Xunit;

namespace Fluxzy.Tests.Cli
{
    public class CliStartOverviewTests
    {
        public static IEnumerable<object[]> GetSingleRequestParameters
        {
            get
            {
                var protocols = new[] { "http11", "http2" };
                var decryptionStatus = new[] { false, true };

                foreach (var protocol in protocols)
                foreach (var decryptStat in decryptionStatus)
                    yield return new object[] { protocol, decryptStat };
            }
        }
        public static IEnumerable<object[]> GetSingleRequestParametersNoDecrypt
        {
            get
            {
                var protocols = new[] { "http11", "http2" };

                foreach (var protocol in protocols)
                    yield return new object[] { protocol };
            }
        }

        [Theory]
        [MemberData(nameof(GetSingleRequestParameters))]
        public async Task Run_Cli(string protocol, bool noDecryption)
        {
            // Arrange 
            var commandLine = "start -l 127.0.0.1/0";

            if (noDecryption)
                commandLine += " -ss";

            var commandLineHost = new FluxzyCommandLineHost(commandLine);

            await using var fluxzyInstance = await commandLineHost.Run();
            using var proxiedHttpClient = new ProxiedHttpClient(fluxzyInstance.ListenPort);

            var requestMessage = new HttpRequestMessage(HttpMethod.Post, $"{TestConstants.GetHost(protocol)}/global-health-check");

            await using var randomStream = new RandomDataStream(48, 23632, true);
            await using var hashedStream = new HashedStream(randomStream);

            requestMessage.Content = new StreamContent(hashedStream);
            requestMessage.Headers.Add("X-Test-Header-256", "That value");

            // Act 
            using var response = await proxiedHttpClient.Client.SendAsync(requestMessage);

            // Assert
            await AssertionHelper.ValidateCheck(requestMessage, hashedStream.Hash, response);
        }


        [Theory]
        [MemberData(nameof(GetSingleRequestParametersNoDecrypt))]
        public async Task Run_Cli_Output_Directory(string protocol)
        {
            // Arrange 

            var directoryName = $"output/{protocol}";
            var commandLine = $"start -l 127.0.0.1/0 -d {directoryName}";

            try
            {
                var commandLineHost = new FluxzyCommandLineHost(commandLine);
                var bodyLength = 0L; 

                await using (var fluxzyInstance = await commandLineHost.Run())
                {
                    using var proxiedHttpClient = new ProxiedHttpClient(fluxzyInstance.ListenPort);

                    var requestMessage = new HttpRequestMessage(HttpMethod.Post, $"{TestConstants.GetHost(protocol)}/global-health-check");

                    await using var randomStream = new RandomDataStream(48, 23632, true);
                    await using var hashedStream = new HashedStream(randomStream);

                    requestMessage.Content = new StreamContent(hashedStream);
                    requestMessage.Headers.Add("X-Test-Header-256", "That value");

                    // Act 
                    using var response = await proxiedHttpClient.Client.SendAsync(requestMessage);


                    bodyLength = response.Content.Headers.ContentLength ?? -1;
                    // Assert
                    await AssertionHelper.ValidateCheck(requestMessage, hashedStream.Hash, response);
                }

                // Assert directory content

                var fullPath = new DirectoryInfo(directoryName).FullName;

                var archiveReader = new DirectoryArchiveReader(directoryName);

                var exchanges = archiveReader.ReadAllExchanges().ToList();
                var connections = archiveReader.ReadAllConnections().ToList();

                var exchange = exchanges.First();
                var connection = connections.First(); 

                Assert.Single(exchanges);
                Assert.Single(connections);

                Assert.Equal(200, exchange.StatusCode);
                Assert.Equal(connection.Id, exchange.ConnectionId);
                Assert.Equal(23632, await archiveReader.GetRequestBody(exchange.Id).Drain(disposeStream: true));
                Assert.Equal(bodyLength, await archiveReader.GetResponseBody(exchange.Id).Drain(disposeStream: true));

                // Verify directory 

            }
            finally
            {
                Directory.Delete(directoryName, true);
            }

        }
    }
}