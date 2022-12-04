﻿// Copyright © 2022 Haga Rakotoharivelo

using System.Threading.Tasks;
using Fluxzy.Clients;
using Fluxzy.Clients.Headers;
using Fluxzy.Rules.Filters;

namespace Fluxzy.Rules.Actions
{
    /// <summary>
    /// Append a response header.
    /// <strong>Note</strong> Headers that alter the connection behaviour will be ignored.
    /// </summary>
    public class AddResponseHeaderAction : Action
    {
        public AddResponseHeaderAction(string headerName, string headerValue)
        {
            HeaderName = headerName;
            HeaderValue = headerValue;
        }

        /// <summary>
        /// Header name
        /// </summary>
        public string HeaderName { get; set;  }

        /// <summary>
        /// Header value
        /// </summary>
        public string HeaderValue { get; set;  }

        public override FilterScope ActionScope => FilterScope.ResponseHeaderReceivedFromRemote;

        public override ValueTask Alter(ExchangeContext context, Exchange? exchange, Connection? connection)
        {
            context.ResponseHeaderAlterations.Add(new HeaderAlterationAdd(HeaderName, HeaderValue));

            return default;
        }

        public override string DefaultDescription =>
            string.IsNullOrWhiteSpace(HeaderName) ?
                $"Add response header" :
                $"Add response header ({HeaderName}, {HeaderValue})";
    }
}