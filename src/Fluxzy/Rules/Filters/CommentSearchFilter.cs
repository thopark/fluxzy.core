// Copyright 2021 - Haga Rakotoharivelo - https://github.com/haga-rak

using System.Collections.Generic;
using Fluxzy.Core;

namespace Fluxzy.Rules.Filters
{
    /// <summary>
    ///     Select exchanges according to comment value
    /// </summary>
    [FilterMetaData(
        LongDescription = "Select exchanges by searching a string pattern into the comment property."
    )]
    public class CommentSearchFilter : StringFilter
    {
        public CommentSearchFilter(string pattern)
            : base(pattern, StringSelectorOperation.Contains)
        {
        }

        public override FilterScope FilterScope => FilterScope.OutOfScope;

        public override string AutoGeneratedName => $"Search in comment \"{Pattern}\"";

        public override IEnumerable<FilterExample> GetExamples()
        {
            yield break;
        }

        protected override IEnumerable<string> GetMatchInputs(
            ExchangeContext? exchangeContext, IAuthority authority, IExchange? exchange)
        {
            if (exchange != null)
                yield return exchange.Comment ?? string.Empty;
        }
    }
}
