// Copyright 2021 - Haga Rakotoharivelo - https://github.com/haga-rak

using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Fluxzy.Clients.H2;
using Fluxzy.Misc.ResizableBuffers;

namespace Fluxzy.Clients.H11
{
    internal static class Http11HeaderBlockReader
    {
        private static readonly byte[] CrLf = { 0x0D, 0x0A, 0x0D, 0x0A };

        /// <summary>
        ///     Read header block from input to buffer. Returns the total header length including double CRLF
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="buffer"></param>
        /// <param name="firstByteReceived"></param>
        /// <param name="headerBlockReceived"></param>
        /// <param name="throwOnError"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        public static async ValueTask<HeaderBlockReadResult>
            GetNext(
                Stream stream, RsBuffer buffer,
                Action firstByteReceived,
                Action headerBlockReceived,
                bool throwOnError = false,
                CancellationToken token = default)
        {
            var bufferIndex = buffer.Memory;
            var totalRead = 0;
            var indexFound = -1;
            var firstBytes = true;

            while (totalRead < buffer.Buffer.Length) {
                var currentRead = await stream.ReadAsync(bufferIndex, token);

                if (currentRead == 0) {
                    if (throwOnError)
                        throw new IOException("Remote connection closed before receiving response");

                    break; // Connection closed
                }

                if (firstBytes) {
                    firstByteReceived?.Invoke();

                    firstBytes = false;
                }

                var start = totalRead - 4 < 0 ? 0 : totalRead - 4;

                var searchBuffer =
                    buffer.Memory.Slice(start, currentRead + (totalRead - start)); // We should look at that buffer 

                totalRead += currentRead;
                bufferIndex = bufferIndex.Slice(currentRead);

                var detected = searchBuffer.Span.IndexOf(CrLf);

                if (detected >= 0) {
                    // FOUND CRLF 
                    indexFound = start + detected + 4;

                    break;
                }

                if (totalRead >= buffer.Buffer.Length) {
                    var bufferIndexLength = totalRead;

                    buffer.Multiply(2);
                    bufferIndex = buffer.Memory.Slice(bufferIndexLength);
                }
            }

            if (indexFound < 0) {
                if (throwOnError) {
                    throw new ExchangeException(
                        $"Double CRLF not detected or header buffer size ({buffer.Buffer.Length}) is less than actual header size.");
                }

                return default;
            }

            headerBlockReceived();

            return new HeaderBlockReadResult(indexFound, totalRead);
        }
    }
}
