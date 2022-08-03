﻿// Copyright © 2022 Haga Rakotoharivelo

using System.Threading.Tasks;
using Fluxzy.Clients;
using Fluxzy.Rules.Filters;

namespace Fluxzy.Rules.Actions
{
    public class UpdateRequestHeaderAction : IAction
    {
        public UpdateRequestHeaderAction(string headerName, string headerValue)
        {
            HeaderName = headerName;
            HeaderValue = headerValue;
        }

        public string HeaderName { get; set;  }

        public string HeaderValue { get; set;  }

        public FilterScope ActionScope => FilterScope.RequestHeaderReceivedFromClient;

        public Task Alter(ExchangeContext context, Exchange exchange, Connection connection)
        {
            exchange.Request.Header.AltReplaceHeaders(
                HeaderName, HeaderValue);

            return Task.CompletedTask;
        }
    }
}