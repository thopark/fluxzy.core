// Copyright 2021 - Haga Rakotoharivelo - https://github.com/haga-rak

using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Fluxzy.Rules.Filters.RequestFilters
{
    /// <summary>
    ///     Select exchanges according to url path. Path includes query string if any.
    /// </summary>
    [FilterMetaData(
        LongDescription = "Select exchanges according to url path. Path includes query string if any."
    )]
    public class PathFilter : StringFilter
    {
        public PathFilter(string pattern)
            : base(pattern)
        {
        }

        [JsonConstructor]
        public PathFilter(string pattern, StringSelectorOperation operation)
            : base(pattern, operation)
        {
        }

        public override FilterScope FilterScope => FilterScope.RequestHeaderReceivedFromClient;

        public override string AutoGeneratedName => $"Path `{Pattern}`";

        public override string GenericName => "Filter by url path";

        public override IEnumerable<FilterExample> GetExamples()
        {
            yield return new FilterExample(
                               "Retains only exchanges having uri starting with API",
                                              new PathFilter("/api", StringSelectorOperation.StartsWith));
        }

        protected override IEnumerable<string> GetMatchInputs(IAuthority authority, IExchange? exchange)
        {
            if (exchange != null)
                yield return exchange.Path;
        }
    }
}
