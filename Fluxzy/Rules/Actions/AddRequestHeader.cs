﻿// Copyright © 2022 Haga Rakotoharivelo

using System.Threading.Tasks;
using Fluxzy.Clients;
using Fluxzy.Rules.Filters;

namespace Fluxzy.Rules.Actions
{
    public class AddRequestHeaderAction : Action
    {
        public AddRequestHeaderAction(string headerName, string headerValue)
        {
            HeaderName = headerName;
            HeaderValue = headerValue;
        }

        public string HeaderName { get; set;  }

        public string HeaderValue { get; set;  }

        public override FilterScope ActionScope => FilterScope.RequestHeaderReceivedFromClient;

        public override ValueTask Alter(ExchangeContext context, Exchange exchange, Connection connection)
        {
            exchange.Request.Header.AltAddHeader(
                HeaderName,
                HeaderValue
                );

            return default;
        }
        public override string DefaultDescription =>
            string.IsNullOrWhiteSpace(HeaderName) ?
                $"Add request header" :
                $"Add request header ({HeaderName}, {HeaderValue})";
    }
}