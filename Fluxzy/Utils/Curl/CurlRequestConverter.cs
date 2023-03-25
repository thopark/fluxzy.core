// Copyright 2021 - Haga Rakotoharivelo - https://github.com/haga-rak

using System;
using System.IO;
using System.Text;
using Fluxzy.Misc;
using Fluxzy.Misc.Streams;
using Fluxzy.Readers;

namespace Fluxzy.Utils.Curl
{
    public class CurlRequestConverter
    {
        private readonly CurlExportFolderManagement _folderManager;

        public CurlRequestConverter(CurlExportFolderManagement folderManager)
        {
            _folderManager = folderManager;
        }

        public CurlCommandResult BuildCurlRequest(
            IArchiveReader archiveReader,
            ExchangeInfo exchange,
            IRunningProxyConfiguration? configuration, bool runInLiveEdit = false)
        {
            var result = new CurlCommandResult(configuration);
            var fullUrl = exchange.FullUrl;

            result.AddArgument(fullUrl);

            // Setting up method 

            var method = exchange.Method;

            if (!method.Equals("GET", StringComparison.OrdinalIgnoreCase))
                result.AddOption("-X", method.ToUpper());

            // Setting up headers 

            foreach (var requestHeader in exchange.GetRequestHeaders()) {
                if (!requestHeader.Forwarded)
                    continue;

                if (requestHeader.Name.Span.StartsWith(":"))
                    continue;

                result.AddOption("-H", $"{requestHeader.Name}: {requestHeader.Value}");
            }

            if (runInLiveEdit) {
                result.AddOption("-H", $"x-fluxzy-live-edit: true");
            }

            using var requestBodyStream = archiveReader.GetRequestBody(exchange.Id);

            if (requestBodyStream != null && requestBodyStream.CanSeek && requestBodyStream.Length > 0) {
                if (requestBodyStream.Length > 1024 * 8) {
                    // We put file on temp 
                    AddBinaryPayload(result, requestBodyStream);
                }
                else {
                    var buffer = new byte[(int) requestBodyStream.Length];

                    requestBodyStream.ReadExact(buffer);

                    if (ArrayTextUtilities.IsText(buffer)) {
                        var bodyString = Encoding.UTF8.GetString(buffer);
                        result.AddOption("--data", bodyString);
                    }
                    else
                        AddBinaryPayload(result, new MemoryStream(buffer));
                }
            }

            return result;
        }

        private void AddBinaryPayload(CurlCommandResult result, Stream requestBodyStream)
        {
            var fullPostPath = _folderManager.GetTemporaryPathFor(result.Id);

            using var fileStream = File.Create(fullPostPath);

            requestBodyStream.CopyTo(fileStream);

            result.FileName = new FileInfo(fullPostPath).Name;
            result.AddOption("--data-binary", $"@{result.FileName}");
        }
    }
}
