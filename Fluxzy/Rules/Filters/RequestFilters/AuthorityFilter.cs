﻿using System.Collections.Generic;

namespace Fluxzy.Rules.Filters.RequestFilters
{
    public class HostFilter : StringFilter
    {
        public HostFilter(string pattern) : base(pattern)
        {
        }

        public HostFilter(string pattern, StringSelectorOperation operation) : base(pattern, operation)
        {
        }

        protected override IEnumerable<string> GetMatchInputs(IAuthority authority, IExchange exchange)
        {
            yield return authority.HostName;
        }

        public override FilterScope FilterScope => FilterScope.RequestHeaderReceivedFromClient;

        public override string FriendlyName => $"Authority {base.FriendlyName}";

    }
}