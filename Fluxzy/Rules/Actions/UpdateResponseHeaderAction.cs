﻿// Copyright © 2022 Haga Rakotoharivelo

using System.Threading.Tasks;
using Fluxzy.Clients;
using Fluxzy.Clients.Headers;
using Fluxzy.Rules.Filters;

namespace Fluxzy.Rules.Actions
{
    /// <summary>
    /// Update and existing response header. If the header does not exists in the original response, the header will be added.
    /// Use {{previous}} keyword to refer to the original value of the header.
    /// <strong>Note</strong> Headers that alter the connection behaviour will be ignored.
    /// </summary>
    public class UpdateResponseHeaderAction : Action
    {
        public UpdateResponseHeaderAction(string headerName, string headerValue)
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
            context.ResponseHeaderAlterations.Add(new HeaderAlterationReplace(HeaderName, HeaderValue));


            return default;
        }
        public override string DefaultDescription => $"Update response header {HeaderName}".Trim();
    }
}