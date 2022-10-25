﻿using Fluxzy.Misc;
using System;

namespace Fluxzy.Rules.Filters.ResponseFilters
{
    public class StatusCodeClientErrorFilter : Filter
    {
        protected override bool InternalApply(IAuthority? authority, IExchange? exchange,
            IFilteringContext? filteringContext)
        {
            if (exchange == null)
                return false;

            var statusCode = exchange.StatusCode;
            return statusCode is >= 400 and < 500; 
        }


        public override Guid Identifier => (GetType().Name + Inverted).GetMd5Guid();

        public override FilterScope FilterScope => FilterScope.ResponseHeaderReceivedFromRemote;

        public override string AutoGeneratedName => $"Client errors (status code is 4XX)";

        public override string GenericName => "Status code 4XX";

        public override string ShortName => "4XX";

        public override bool PreMadeFilter => true;
    }
}