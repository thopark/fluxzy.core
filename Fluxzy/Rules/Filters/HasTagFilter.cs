﻿using System.Linq;

namespace Fluxzy.Rules.Filters
{
    public class HasTagFilter : Filter
    {
        protected override bool InternalApply(IAuthority? authority, IExchange? exchange, IFilteringContext? filteringContext)
        {
            return exchange?.Tags?.Any() ?? false;
        }

        public override FilterScope FilterScope => FilterScope.OutOfScope;

        public override string AutoGeneratedName { get; } = "Has any tag";

        public override bool PreMadeFilter { get; } = true;
    }
}