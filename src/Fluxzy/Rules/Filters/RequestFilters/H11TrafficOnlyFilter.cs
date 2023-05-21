// Copyright 2021 - Haga Rakotoharivelo - https://github.com/haga-rak

using System;
using System.Collections.Generic;
using Fluxzy.Misc;

namespace Fluxzy.Rules.Filters.RequestFilters
{
    /// <summary>
    ///     Select HTTP/1.1 traffic only
    /// </summary>
    [FilterMetaData(
        LongDescription = "Select HTTP/1.1 exchanges only."
    )]
    public class H11TrafficOnlyFilter : Filter
    {
        public override FilterScope FilterScope => FilterScope.RequestHeaderReceivedFromClient;

        public override string GenericName => "HTTP/1.1 only";

        public override string AutoGeneratedName { get; } = "HTTP/1.1 only";

        public override string ShortName => "h11";

        public override bool PreMadeFilter => true;

        protected override bool InternalApply(
            IAuthority authority, IExchange? exchange,
            IFilteringContext? filteringContext)
        {
            return exchange?.HttpVersion == "HTTP/1.1";
        }

        public override IEnumerable<FilterExample> GetExamples()
        {
            var defaultSample = GetDefaultSample();

            if (defaultSample != null)
                yield return defaultSample;
        }
    }
}
