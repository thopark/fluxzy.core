// Copyright 2021 - Haga Rakotoharivelo - https://github.com/haga-rak

using System.Collections.Generic;
using Fluxzy.Core;
using Fluxzy.Rules.Extensions;

namespace Fluxzy.Rules.Filters.RequestFilters
{
    /// <summary>
    ///     Select exchanges according to request method.
    /// </summary>
    [FilterMetaData(
        LongDescription = "Select exchanges according to request method."
    )]
    public class MethodFilter : StringFilter
    {
        public MethodFilter(string pattern)
            : base(pattern, StringSelectorOperation.Exact)
        {
        }

        public override FilterScope FilterScope => FilterScope.RequestHeaderReceivedFromClient;

        public override string ShortName => Pattern?.ToLower() ?? "meth.";

        public override string AutoGeneratedName => $"Request method {base.AutoGeneratedName}";

        public override string GenericName => "Filter by HTTP method";

        protected override IEnumerable<string> GetMatchInputs(
            ExchangeContext? exchangeContext, IAuthority authority, IExchange? exchange)
        {
            if (exchange != null)
                yield return exchange.Method;
        }

        protected override bool InternalApply(
            ExchangeContext? exchangeContext, IAuthority authority, IExchange? exchange,
            IFilteringContext? filteringContext)
        {
            CaseSensitive = false;

            return base.InternalApply(exchangeContext, authority, exchange, filteringContext);
        }

        public override IEnumerable<FilterExample> GetExamples()
        {
            yield return new FilterExample(
                "Select exchanges having TRACE request method.",
                new MethodFilter("TRACE")
            );
        }
    }

    public static class MethodFilterExtensions
    {
        public static IConfigureActionBuilder WhenMethodIs(this IConfigureFilterBuilder builder, string method)
        {
            return builder.When(new MethodFilter(method));
        }

        public static IConfigureActionBuilder WhenMethodIsGet(this IConfigureFilterBuilder builder)
        {
            return builder.WhenMethodIs("GET");
        }

        public static IConfigureActionBuilder WhenMethodIsPost(this IConfigureFilterBuilder builder)
        {
            return builder.WhenMethodIs("POST");
        }

        public static IConfigureActionBuilder WhenMethodIsPut(this IConfigureFilterBuilder builder)
        {
            return builder.WhenMethodIs("PUT");
        }
    }
}
