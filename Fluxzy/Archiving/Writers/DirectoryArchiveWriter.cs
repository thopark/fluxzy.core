﻿using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Fluxzy.Misc.Streams;

namespace Fluxzy.Writers
{
    public class DirectoryArchiveWriter : RealtimeArchiveWriter
    {
        private readonly string _baseDirectory;
        private readonly string _captureDirectory;
        private readonly string _contentDirectory;

        public DirectoryArchiveWriter(string baseDirectory)
        {
            _baseDirectory = baseDirectory;
            _contentDirectory = Path.Combine(baseDirectory, "contents");
            _captureDirectory = Path.Combine(baseDirectory, "captures");

            Directory.CreateDirectory(_contentDirectory);
            Directory.CreateDirectory(_captureDirectory);
        }

        public override async Task Update(ExchangeInfo exchangeInfo, CancellationToken cancellationToken)
        {
            var exchangePath = DirectoryArchiveHelper.GetExchangePath(_baseDirectory, exchangeInfo);

            DirectoryArchiveHelper.CreateDirectory(exchangePath); 

            await using var fileStream = File.Create(exchangePath);
            await JsonSerializer.SerializeAsync(fileStream, exchangeInfo, GlobalArchiveOption.JsonSerializerOptions,
                cancellationToken);
        }

        public override async Task Update(ConnectionInfo connectionInfo, CancellationToken cancellationToken)
        {
            var connectionPath = DirectoryArchiveHelper.GetConnectionPath(_baseDirectory, connectionInfo);

            DirectoryArchiveHelper.CreateDirectory(connectionPath);

            await using var fileStream = File.Create(connectionPath);
            await JsonSerializer.SerializeAsync(fileStream, connectionInfo, GlobalArchiveOption.JsonSerializerOptions,
                cancellationToken);
        }

        public override Stream CreateRequestBodyStream(int exchangeId)
        {
            var path = Path.Combine(_contentDirectory, $"req-{exchangeId}.data");
            return File.Create(path);
        }

        public override Stream CreateResponseBodyStream(int exchangeId)
        {
            var path = Path.Combine(_contentDirectory, $"res-{exchangeId}.data");
            return File.Create(path);
        }

        public override string GetDumpfilePath(int connectionId)
        {
            return Path.Combine(_captureDirectory, $"{connectionId}.pcap");
        }
    }
}