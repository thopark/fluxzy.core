// Copyright 2021 - Haga Rakotoharivelo - https://github.com/haga-rak

using System.Collections.Generic;
using System.Text.Json.Serialization;
using Fluxzy.Core;

namespace Fluxzy.Rules.Filters
{
    /// <summary>
    ///     Select exchanges according to upstream ip address
    /// </summary>
    [FilterMetaData(
        LongDescription = "Select exchanges according to upstream IP address. Full IP notation is used from IPv6."
    )]
    public class IpEgressFilter : StringFilter
    {
        public IpEgressFilter(string pattern)
            : base(pattern)
        {
        }

        [JsonConstructor]
        public IpEgressFilter(string pattern, StringSelectorOperation operation)
            : base(pattern, operation)
        {
        }

        public override FilterScope FilterScope => FilterScope.OnAuthorityReceived;

        public override string GenericName => "Filter by Egress IP Address";

        public override string AutoGeneratedName => $"IP out : `{Pattern}`";

        public override string ShortName => "ip out";

        public override IEnumerable<FilterExample> GetExamples()
        {
            yield return new FilterExample(
                "Retains only exchanges where the destination address is `212.12.14.0/24`",
                new IpEgressFilter("212.12.14", StringSelectorOperation.StartsWith));

            yield return new FilterExample(
                "Retains only exchanges where the destination address is `2a01:cb00:7e2:5000:10d5:70df:665:c654` (IPv6)",
                new IpEgressFilter("2a01:cb00:7e2:5000:10d5:70df:665:c654", StringSelectorOperation.Exact));
        }

        protected override IEnumerable<string> GetMatchInputs(
            ExchangeContext? exchangeContext, IAuthority authority, IExchange? exchange)
        {
            yield return exchange?.EgressIp ?? string.Empty;
        }
    }
}
