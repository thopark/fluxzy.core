﻿// Copyright © 2022 Haga Rakotoharivelo

using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

namespace Fluxzy.Rules.Filters
{
    /// <summary>
    /// A filter collection is a combination of multiple filter with a merging operator (OR / AND).
    /// <b>Specific consideration</b> A blank filter collection (no children) will always pass if operator is AND and will
    /// always fail if operator is OR
    /// 
    /// </summary>
    public class FilterCollection : Filter
    {
        public List<Filter> Children { get; set; } = new();

        public SelectorCollectionOperation Operation { get; set; }

        public override FilterScope FilterScope => Children.Select(c => c.FilterScope)
                                                           .DefaultIfEmpty(FilterScope.OnAuthorityReceived).Max(c => c);

        public override string AutoGeneratedName => $"Combination of {Children.Count} filter(s)";

        public override string ShortName => ExplicitShortName ?? "comb.";

        public string? ExplicitShortName { get; set; }

        public virtual string GenericName => "Filter collection";

        [JsonConstructor]
        public FilterCollection()
        {
        }

        public FilterCollection(params Filter[] filters)
        {
            Children = filters?.ToList() ?? new List<Filter>();
        }

        protected override bool InternalApply(IAuthority authority, IExchange? exchange,
            IFilteringContext? filteringContext)
        {
            foreach (var child in Children)
            {
                var res = child.Apply(authority, exchange, filteringContext);

                if (Operation == SelectorCollectionOperation.And && !res)
                    return false;

                if (Operation == SelectorCollectionOperation.Or && res)
                    return true;
            }

            return Operation == SelectorCollectionOperation.And;
        }
    }
}
