﻿// Copyright 2021 - Haga Rakotoharivelo - https://github.com/haga-rak

namespace Fluxzy.Rules.Filters
{
    /// <summary>
    ///     Select nothing
    /// </summary>
    public class NoFilter : Filter
    {
        public override FilterScope FilterScope => FilterScope.OnAuthorityReceived;

        public override string GenericName => "Block all";

        public override bool PreMadeFilter => true;

        protected override bool InternalApply(
            IAuthority authority, IExchange? exchange,
            IFilteringContext? filteringContext)
        {
            return false;
        }
    }
}
