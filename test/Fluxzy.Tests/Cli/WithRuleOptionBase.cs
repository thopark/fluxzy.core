// Copyright 2021 - Haga Rakotoharivelo - https://github.com/haga-rak

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Fluxzy.Tests.Cli.Scaffolding;

namespace Fluxzy.Tests.Cli
{
    public class WithRuleOptionBase : IAsyncDisposable
    {
        private ProxyInstance? _fluxzyInstance;

        protected ProxiedHttpClient? Client { get; private set; }

        private string? _ruleFile;

        public CookieContainer CookieContainer { get; } = new();

        private readonly List<FileInfo> _tempFiles = new();

        protected FileInfo GetTempFile()
        {
            var uniqueIdentifier = Guid.NewGuid().ToString();
            var tempFile = new FileInfo($"{uniqueIdentifier}.yml");
            _tempFiles.Add(tempFile);
            return tempFile;
        }

        protected async Task<HttpResponseMessage> Exec(string yamlContent, 
            HttpRequestMessage requestMessage,
            bool allowAutoRedirect = true, bool automaticDecompression = false, bool useBouncyCastle = false)
        {
            // Arrange 
            var commandLine = "start -l 127.0.0.1:0";
            var uniqueIdentifier = Guid.NewGuid().ToString();

            _ruleFile = $"{uniqueIdentifier}.yml";
            
            await File.WriteAllTextAsync(_ruleFile, yamlContent);

            commandLine += $" -r {_ruleFile}";

            if (useBouncyCastle) {
                commandLine += " --bouncy-castle";
            }

            var commandLineHost = new FluxzyCommandLineHost(commandLine);

            _fluxzyInstance = await commandLineHost.Run();

            Client = new ProxiedHttpClient(_fluxzyInstance.ListenPort,
                cookieContainer: CookieContainer, allowAutoRedirect: allowAutoRedirect, automaticDecompression: automaticDecompression);

            return  await Client.Client.SendAsync(requestMessage);
        }
        
        public async ValueTask DisposeAsync()
        { 
            if (_ruleFile != null && File.Exists(_ruleFile))
                File.Delete(_ruleFile);


            Client?.Dispose();

            if (_fluxzyInstance != null)
                await _fluxzyInstance.DisposeAsync();

            foreach (var tempFile in _tempFiles) {
                if (tempFile.Exists)
                    tempFile.Delete();
            }
        }
    }
}
