// Copyright 2021 - Haga Rakotoharivelo - https://github.com/haga-rak

using System;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Fluxzy.Clients.DotNetBridge;
using Fluxzy.Misc.Streams;
using Fluxzy.Tests._Fixtures;
using Xunit;

namespace Fluxzy.Tests
{
    public class Http11SingleCallUrl
    {
        [Fact]
        public async Task Get_IIS()
        {
            using var handler = new FluxzyHttp11Handler();
            using var httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };

            var requestMessage = new HttpRequestMessage(
                HttpMethod.Get,
                "https://extranet.2befficient.fr/Scripts/Core?v=RG4zfPZTCmDTC0sCJZC1Fx9GEJ_Edk7FLfh_lQ"
            );

            var response = await httpClient.SendAsync(requestMessage);

            Assert.True(response.IsSuccessStatusCode);
        }

        // [Fact : TODO à corriger
        public async Task Get_Error_Case()
        {
            using var handler = new FluxzyHttp11Handler();
            using var httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };

            var requestMessage = new HttpRequestMessage(
                HttpMethod.Get,
                "https://fr.wiktionary.org/w/skins/Vector/resources/common/images/arrow-down.svg?9426f"
            );

            var response = await httpClient.SendAsync(requestMessage);

            Assert.True(response.IsSuccessStatusCode);
        }

        [Fact]
        public async Task Get_Control_Single_Headers()
        {
            using var handler = new FluxzyHttp11Handler();
            using var httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };

            var requestMessage = new HttpRequestMessage(
                HttpMethod.Get,
                "https://registry.2befficient.io:40300/get"
            );

            var response = await httpClient.SendAsync(requestMessage);
            var contentText = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            Assert.True(response.IsSuccessStatusCode);
            AssertHelpers.ControlHeaders(contentText, requestMessage);
        }

        [Fact]
        public async Task Get_With_200_Simple()
        {
            using var handler = new FluxzyHttp11Handler();
            using var httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };

            var requestMessage = new HttpRequestMessage(
                HttpMethod.Get,
                "https://registry.2befficient.io:40300/ip"
            );

            var response = await httpClient.SendAsync(requestMessage);
            var contentText = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            Assert.True(response.IsSuccessStatusCode);
            AssertHelpers.ControlHeaders(contentText, requestMessage);
        }

        [Fact]
        public async Task Get_With_204_No_Body()
        {
            using var handler = new FluxzyHttp11Handler();
            using var httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };

            var requestMessage = new HttpRequestMessage(
                HttpMethod.Get,
                "https://registry.2befficient.io:40300/status/204"
            );

            var response = await httpClient.SendAsync(requestMessage);
            var contentText = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            Assert.True(response.IsSuccessStatusCode);
            Assert.True(contentText == string.Empty);
        }

        [Fact]
        public async Task Get_File_Small_UnknownSize()
        {
            using var handler = new FluxzyHttp11Handler();
            using var httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };

            var requestMessage = new HttpRequestMessage(
                HttpMethod.Get,
                "https://sandbox.smartizy.com/content-produce-unpredictable/130000/130000"
            );

            var response = await httpClient.SendAsync(requestMessage);
            var contentLength = await (await response.Content.ReadAsStreamAsync()).DrainAsync();

            var actualLength =
                int.Parse(response.Headers.GetValues("actual-content-length").First());

            Assert.True(response.IsSuccessStatusCode);
            Assert.Equal(actualLength, contentLength);
        }

        [Fact]
        public async Task Get_File_Large_UnknownSize()
        {
            using var handler = new FluxzyHttp11Handler();
            using var httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };

            var requestMessage = new HttpRequestMessage(
                HttpMethod.Get,
                "https://sandbox.smartizy.com:5001/content-produce-unpredictable/2300000/2300000"
            );

            var response = await httpClient.SendAsync(requestMessage);
            var array = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);

            var actualLength =
                int.Parse(response.Headers.GetValues("actual-content-length").First());

            Assert.True(response.IsSuccessStatusCode);
            Assert.Equal(actualLength, array.Length);
        }

        [Fact]
        public async Task Get_Control_Duplicate_Headers()
        {
            using var handler = new FluxzyHttp11Handler();
            using var httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };

            var requestMessage = new HttpRequestMessage(
                HttpMethod.Get,
                "https://registry.2befficient.io:40300/get"
            );

            requestMessage.Headers.Add("x-favorite-header", "1");
            requestMessage.Headers.Add("X-fAVorite-header", "2");

            var response = await httpClient.SendAsync(requestMessage);
            var contentText = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            Assert.True(response.IsSuccessStatusCode);
            AssertHelpers.ControlHeaders(contentText, requestMessage);
        }

        [Fact]
        public async Task Post_Data_Lt_Max_Frame()
        {
            using var handler = new FluxzyHttp11Handler();
            using var httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };

            var requestMessage = new HttpRequestMessage(
                HttpMethod.Post,
                "https://registry.2befficient.io:40300/post"
            );

            var bufferString = new string('a', 16 * 1024 - 9);

            var content = new StringContent(bufferString, Encoding.UTF8);
            content.Headers.ContentLength = content.Headers.ContentLength;

            requestMessage.Content = content;

            var response = await httpClient.SendAsync(requestMessage);
            var contentText = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            Assert.True(response.IsSuccessStatusCode);
            AssertHelpers.ControlHeaders(contentText, requestMessage);
        }

        [Fact]
        public async Task Post_Data_Gt_Max_Frame()
        {
            using var handler = new FluxzyHttp11Handler();
            using var httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };

            var requestMessage = new HttpRequestMessage(
                HttpMethod.Post,
                "https://registry.2befficient.io:40300/post"
            );

            var bufferString = new string('a', 16 * 1024 + 10);

            var content = new StringContent(bufferString, Encoding.UTF8);
            content.Headers.ContentLength = content.Headers.ContentLength;

            requestMessage.Content = content;

            requestMessage.ToHttp11String();

            var response = await httpClient.SendAsync(requestMessage);
            var contentText = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            Assert.True(response.IsSuccessStatusCode);
            AssertHelpers.ControlHeaders(contentText, requestMessage);
        }

        [Fact]
        public async Task Post_Data_Unknown_Size()
        {
            using var handler = new FluxzyHttp11Handler();
            using var httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };

            var requestMessage = new HttpRequestMessage(
                HttpMethod.Post,
                "https://registry.2befficient.io:40300/post"
            );

            using var randomStream = new RandomDataStream(9, 1024 * 124);
            var content = new StreamContent(randomStream, 8192);

            requestMessage.Content = content;

            var response = await httpClient.SendAsync(requestMessage);
            var contentText = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            Assert.True(response.IsSuccessStatusCode);

            AssertHelpers
                .ControlHeaders(contentText, requestMessage)
                .ControlBody(randomStream.Hash);
        }

        [Fact]
        public async Task Get_With_InvalidHeaders()
        {
            using var handler = new FluxzyHttp11Handler();
            using var httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };

            var requestMessage = new HttpRequestMessage(
                HttpMethod.Get,
                "https://registry.2befficient.io:40300/get"
            );

            requestMessage.Headers.Add("Connection", "Keep-alive");

            var response = await httpClient.SendAsync(requestMessage);
            var contentText = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            Assert.True(response.IsSuccessStatusCode);
        }

        [Fact]
        public async Task Get_With_Extra_Column_Header()
        {
            using var handler = new FluxzyHttp11Handler();
            using var httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };

            var requestMessage = new HttpRequestMessage(
                HttpMethod.Get,
                "https://registry.2befficient.io:40300/get"
            );

            requestMessage.Headers.Add("x-Header-a", "ads");

            var response = await httpClient.SendAsync(requestMessage);

            var contentText = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            Assert.True(response.IsSuccessStatusCode);
            AssertHelpers.ControlHeaders(contentText, requestMessage);
        }

        [Fact]
        public async Task Get_And_Cancel()
        {
            using var handler = new FluxzyHttp11Handler();
            using var httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };

            var requestMessage = new HttpRequestMessage(
                HttpMethod.Get,
                "https://registry.2befficient.io:40300/get"
            );

            var source = new CancellationTokenSource();

            await Assert.ThrowsAsync<TaskCanceledException>(async () => {
                var responsePromise = httpClient.SendAsync(requestMessage, source.Token);
                source.Cancel();
                await responsePromise;
            });
        }
    }
}
