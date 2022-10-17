﻿using System;

namespace Fluxzy.Rules.Filters.ResponseFilters
{
    public class StatusCodeClientErrorFilter : Filter
    {
        protected override bool InternalApply(IAuthority authority, IExchange exchange)
        {
            var statusCode = exchange.StatusCode;
            return statusCode is >= 400 and < 500; 
        }


        public override Guid Identifier => Guid.Parse("7DB577F4-7938-4D6B-90F6-55EC6A116167");

        public override FilterScope FilterScope => FilterScope.ResponseHeaderReceivedFromRemote;

        public override string AutoGeneratedName => $"Client errors (status code is 4XX)";

        public override string GenericName => "Status code 4XX";

        public override string ShortName => "4XX";

        public override bool PreMadeFilter => true;
    }
}