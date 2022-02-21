﻿// Copyright © 2022 Haga Rakotoharivelo

using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Echoes.H2;
using Echoes.H2.Encoder.Utils;
using Echoes.IO;

namespace Echoes.H11
{
    internal class Http11PoolProcessing
    {
        private static readonly ReadOnlyMemory<char> Space = " ".AsMemory();
        private static readonly ReadOnlyMemory<char> LineFeed = "\r\n".AsMemory();
        private static readonly ReadOnlyMemory<char> Protocol = " HTTP/1.1".AsMemory();
        private static readonly ReadOnlyMemory<char> HostHeader = "Host: ".AsMemory();

        private readonly ITimingProvider _timingProvider;
        private readonly ClientSetting _clientSetting;
        private readonly Http11Parser _parser;
        private readonly H1Logger _logger;

        private static readonly byte[] CrLf = { 0x0D, 0x0A, 0x0D, 0x0A };

        public Http11PoolProcessing(
            ITimingProvider timingProvider,
            ClientSetting clientSetting,
            Http11Parser parser, H1Logger logger)
        {
            _timingProvider = timingProvider;
            _clientSetting = clientSetting;
            _parser = parser;
            _logger = logger;
        }

        private static int count = 0; 

        /// <summary>
        /// Process the exchange
        /// </summary>
        /// <param name="exchange"></param>
        /// <param name="cancellationToken"></param>
        /// <returns>True if remote server close connection</returns>
        public async Task<bool> Process(Exchange exchange, CancellationToken cancellationToken)
        {
            // Here is the opportunity to change header 
            var bufferRaw = new byte[_clientSetting.MaxHeaderSize];
            Memory<byte> headerBuffer = bufferRaw;

            exchange.Connection.AddNewRequestProcessed();

            exchange.Metrics.RequestHeaderSending = _timingProvider.Instant();

            _logger.Trace(exchange.Id, () => $"Begin writing header");
            var headerLength = exchange.Request.Header.WriteHttp11(headerBuffer.Span, true);


            // Sending request header 

            await exchange.Connection.WriteStream.WriteAsync(headerBuffer.Slice(0, headerLength), cancellationToken);

            _logger.Trace(exchange.Id, () => $"Header sent");

            exchange.Metrics.TotalSent += headerLength;
            exchange.Metrics.RequestHeaderSent = _timingProvider.Instant();

            // Sending request body 

            if (exchange.Request.Body != null)
            {
                var totalBodySize = await
                    exchange.Request.Body.CopyDetailed(exchange.Connection.WriteStream, 1024 * 8,
                        (_) => { }, cancellationToken).ConfigureAwait(false);
                exchange.Metrics.TotalSent += totalBodySize;
            }

            _logger.Trace(exchange.Id, () => $"Body sent");

            var headerBlockDetectResult = await
                DetectHeaderBlock(exchange.Connection.ReadStream, headerBuffer,
                    () => exchange.Metrics.ResponseHeaderStart = _timingProvider.Instant(),
                    () => exchange.Metrics.ResponseHeaderEnd = _timingProvider.Instant(),
                    true,
                    cancellationToken);

            Memory<char> headerContent = new char[headerBlockDetectResult.HeaderLength];

            Encoding.ASCII
                .GetChars(headerBuffer.Slice(0, headerBlockDetectResult.HeaderLength).Span, headerContent.Span);

            
            exchange.Response.Header = new ResponseHeader(
                headerContent, exchange.Authority.Secure, _parser);

            _logger.TraceResponse(exchange);
            

            var shouldCloseConnection =
                exchange.Response.Header.ConnectionCloseRequest
                || exchange.Response.Header.ChunkedBody; // Chunked body response always en with connection close 
            
            if (!exchange.Response.Header.HasResponseBody())
            {
                // We close the connection because
                // many web server still sends a content-body with a 304 response 
                // https://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html 10.3.5

                shouldCloseConnection = true; 

                exchange.Metrics.ResponseBodyStart = exchange.Metrics.ResponseBodyEnd = _timingProvider.Instant();
                exchange.Response.Body = StreamUtils.EmptyStream;

                exchange.ExchangeCompletionSource.TrySetResult(true);

                _logger.Trace(exchange.Id, () => $"No response body");

                return true;
            }

            Stream bodyStream = exchange.Connection.ReadStream;

            Interlocked.Increment(ref count);

            if (headerBlockDetectResult.HeaderLength < headerBlockDetectResult.TotalReadLength)
            {
                // Concat the extra body bytes read while retrieving header
                bodyStream = new CombinedReadonlyStream(
                    shouldCloseConnection,
                    new MemoryStream(bufferRaw, headerBlockDetectResult.HeaderLength, headerBlockDetectResult.TotalReadLength -
                        headerBlockDetectResult.HeaderLength
                    ),
                    exchange.Connection.ReadStream
                );
            }

            if (exchange.Response.Header.ChunkedBody)
            {
                bodyStream = new ChunkedTransferReadStream(bodyStream, shouldCloseConnection);
            }
       
            if (exchange.Response.Header.ContentLength > 0)
            {
                bodyStream = new ContentBoundStream(bodyStream, exchange.Response.Header.ContentLength);
            }

            exchange.Response.Body =
                new MetricsStream(bodyStream,
                    () =>
                    {
                        exchange.Metrics.ResponseBodyStart = _timingProvider.Instant();
                        _logger.Trace(exchange.Id, () => $"First body bytes read");
                    },
                    (length) =>
                    {
                        exchange.Metrics.ResponseBodyEnd = _timingProvider.Instant();
                        exchange.Metrics.TotalReceived += length;
                        exchange.ExchangeCompletionSource.SetResult(shouldCloseConnection);
                        _logger.Trace(exchange.Id, () => $"Last body bytes end : {length} total bytes");
                    },
                    (exception) =>
                    {
                        exchange.Metrics.ResponseBodyEnd = _timingProvider.Instant();
                        exchange.ExchangeCompletionSource.SetException(exception);

                        _logger.Trace(exchange.Id, () => $"Read error : {exception}");
                    },
                    cancellationToken
                 )
               ;

            return shouldCloseConnection;
        }


        /// <summary>
        /// Read header block from input to buffer. Returns the total header length including double CRLF
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="buffer"></param>
        /// <param name="firstByteReceived"></param>
        /// <param name="headerBlockReceived"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        public static async ValueTask<HeaderBlockReadResult>
            DetectHeaderBlock(
            Stream stream, Memory<byte> buffer, 
                Action firstByteReceived, 
                Action headerBlockReceived, 
                bool throwOnError = false, 
                CancellationToken token = default)
        {
            var bufferIndex = buffer;
            var totalRead = 0;
            var indexFound = -1;
            var firstBytes = true;

            while (totalRead < buffer.Length)
            {
                var currentRead = await stream.ReadAsync(bufferIndex, token);

                if (currentRead == 0)
                {
                    if (throwOnError)
                        throw new IOException("Remote connection closed before receiving response");

                    break; // Connection closed
                }

                if (firstBytes)
                {
                    firstByteReceived?.Invoke();

                    firstBytes = false;
                }

                var start = totalRead - 4 < 0 ? 0 : (totalRead - 4);

                var searchBuffer = buffer.Slice(start, currentRead + (totalRead - start)); // We should look at that buffer 

                totalRead += currentRead;
                bufferIndex = bufferIndex.Slice(currentRead);

                var detected = searchBuffer.Span.IndexOf(CrLf);

                if (detected >= 0)
                {
                    // FOUND CRLF 
                    indexFound = start + detected + 4;
                    break;
                }
            }

            if (indexFound < 0)
            {
                if (throwOnError)
                    throw new ExchangeException(
                        $"Double CRLF not detected or header buffer size ({buffer.Length}) is less than actual header size.");

                return default; 
            }

            headerBlockReceived();

            return new HeaderBlockReadResult(indexFound, totalRead);
        }


    }
}