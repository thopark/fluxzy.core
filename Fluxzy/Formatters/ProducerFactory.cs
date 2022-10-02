﻿// Copyright © 2022 Haga Rakotoharivelo

using System.Collections.Generic;
using System.Threading.Tasks;
using Fluxzy.Formatters.Producers.Requests;
using Fluxzy.Screeners;

namespace Fluxzy.Formatters
{
    public class ProducerFactory
    {
        private readonly IArchiveReaderProvider _archiveReaderProvider;
        private readonly ProducerSettings _producerSettings;

        private static readonly List<IFormattingProducer<FormattingResult>> RequestProducers = new()
        {
            new RequestJsonBodyProducer(),
            new AuthorizationBasicProducer(),
            new AuthorizationBearerProducer(),
            new QueryStringProducer(),
            new RequestCookieProducer(),
            new RequestBodyAnalysis(),
            new RequestTextBodyProducer(),
            new AuthorizationProducer(),
            new RawRequestHeaderProducer(),
        };

        public ProducerFactory(IArchiveReaderProvider archiveReaderProvider, ProducerSettings producerSettings)
        {
            _archiveReaderProvider = archiveReaderProvider;
            _producerSettings = producerSettings;
        }

        public async Task<ProducerContext?> GetProducerContext(int exchangeId)
        {
            var archiveReader = await _archiveReaderProvider.Get();

            if (archiveReader == null)
                return null;  

            var exchangeInfo = archiveReader.ReadExchange(exchangeId);

            if (exchangeInfo == null)
            {
                return null;
            }

            return new ProducerContext(exchangeInfo, archiveReader, _producerSettings);
        }
        

        public async IAsyncEnumerable<FormattingResult> GetRequestFormattedResults(int exchangeId)
        {
            using var formattingProducerContext = await GetProducerContext(exchangeId);

            if (formattingProducerContext == null)
                yield break;
            

            foreach (var producer in RequestProducers)
            {
                var result = producer.Build(formattingProducerContext.Exchange, formattingProducerContext);

                if (result != null)
                    yield return result;
            }
        }
    }

    
}