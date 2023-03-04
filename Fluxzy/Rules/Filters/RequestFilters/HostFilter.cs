﻿// Copyright 2021 - Haga Rakotoharivelo - https://github.com/haga-rak

using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Fluxzy.Rules.Filters.RequestFilters
{
    /// <summary>
    ///     Select exchange according to host. The host is taken from the Host header (HTTP/1.1) or the :authority header (H2).
    /// </summary>
    [FilterMetaData(
        LongDescription =
            "Select exchange according to hostname (excluding port). To select authority (combination of host:port), use <goto>AuthorityFilter</goto>."
    )]
    public class HostFilter : StringFilter
    {
        public HostFilter(string pattern)
            : this(pattern, StringSelectorOperation.Exact)
        {
        }

        [JsonConstructor]
        public HostFilter(string pattern, StringSelectorOperation operation)
            : base(pattern, operation)
        {
        }

        public override FilterScope FilterScope => FilterScope.OnAuthorityReceived;

        public override string? ShortName => "host";

        public override string AutoGeneratedName => $"Hostname `{Pattern}`";

        public override string GenericName => "Filter by host";

        public override bool Common { get; set; } = true;

        protected override IEnumerable<string> GetMatchInputs(IAuthority? authority, IExchange? exchange)
        {
            var hostName = authority?.HostName ?? exchange?.KnownAuthority;

            if (hostName != null)
                yield return hostName;
        }
    }
}
