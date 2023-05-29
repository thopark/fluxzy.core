// Copyright 2021 - Haga Rakotoharivelo - https://github.com/haga-rak

using System;
using System.Collections.Generic;
using Fluxzy.Clients;
using Fluxzy.Misc;

namespace Fluxzy.Rules.Filters.ResponseFilters
{
    [FilterMetaData(
        LongDescription = "Select exchanges that fails due to network error."
    )]
    public class NetworkErrorFilter : Filter
    {
        public override Guid Identifier => (GetType().Name + Inverted).GetMd5Guid();

        public override FilterScope FilterScope => FilterScope.ResponseHeaderReceivedFromRemote;

        public override string AutoGeneratedName => "Network errors only";

        public override string GenericName => "Network errors (528)";

        public override string ShortName => "neterr.";

        public override bool PreMadeFilter => true;

        protected override bool InternalApply(
            ExchangeContext? exchangeContext, IAuthority authority, IExchange? exchange,
            IFilteringContext? filteringContext)
        {
            if (exchange == null)
                return false;

            return exchange.StatusCode == 528;
        }

        public override IEnumerable<FilterExample> GetExamples()
        {
            var defaultSample = GetDefaultSample();

            if (defaultSample != null)
                yield return defaultSample;
        }
    }
}
