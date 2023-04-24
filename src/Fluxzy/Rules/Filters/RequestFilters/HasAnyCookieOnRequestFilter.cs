// Copyright 2021 - Haga Rakotoharivelo - https://github.com/haga-rak

using System.Linq;
using Fluxzy.Clients.H2.Encoder;
using Fluxzy.Formatters.Producers.Requests;

namespace Fluxzy.Rules.Filters.RequestFilters
{
    [FilterMetaData(
        LongDescription = "Exchange having any request cookie"
    )]
    public class HasAnyCookieOnRequestFilter : Filter
    {
        public override FilterScope FilterScope  => FilterScope.RequestHeaderReceivedFromClient;

        public override string AutoGeneratedName => "Having any request cookie";

        public override string GenericName => "Cookie";

        public override string ShortName => "Has any cookie";

        public override bool PreMadeFilter => true;

        protected override bool InternalApply(
            IAuthority authority, IExchange? exchange, IFilteringContext? filteringContext)
        {
            if (exchange == null)
                return false; 

            var requestCookies =
                HttpHelper.ReadRequestCookies(exchange.GetRequestHeaders().Select(h => (GenericHeaderField)h));

            return requestCookies.Any();
        }
    }
}
