// Copyright 2021 - Haga Rakotoharivelo - https://github.com/haga-rak

using System.Collections.Generic;
using System.Threading.Tasks;
using Fluxzy.Clients;
using Fluxzy.Clients.Headers;
using Fluxzy.Core.Breakpoints;

namespace Fluxzy.Rules.Actions
{
    /// <summary>
    ///     Update and existing request header. If the header does not exists in the original request, the header will be
    ///     added.
    ///     Use {{previous}} keyword to refer to the original value of the header.
    ///     <strong>Note</strong> Headers that alter the connection behaviour will be ignored.
    /// </summary>
    [ActionMetadata(
        "Update and existing request header. If the header does not exists in the original request, the header will be added. <br/>" +
        "Use {{previous}} keyword to refer to the original value of the header. <br/>" +
        "<strong>Note</strong> Headers that alter the connection behaviour will be ignored.")]
    public class UpdateRequestHeaderAction : Action
    {
        public UpdateRequestHeaderAction(string headerName, string headerValue)
        {
            HeaderName = headerName;
            HeaderValue = headerValue;
        }

        /// <summary>
        ///     Header name
        /// </summary>
        [ActionDistinctive]
        public string HeaderName { get; set; }

        /// <summary>
        ///     Header value
        /// </summary>
        [ActionDistinctive]
        public string HeaderValue { get; set; }

        public override FilterScope ActionScope => FilterScope.RequestHeaderReceivedFromClient;

        public override string DefaultDescription => $"Update request header {HeaderName}".Trim();

        public override ValueTask InternalAlter(
            ExchangeContext context, Exchange? exchange, Connection? connection, FilterScope scope,
            BreakPointManager breakPointManager)
        {
            context.RequestHeaderAlterations.Add(new HeaderAlterationReplace(HeaderName.EvaluateVariable(context)!,
                HeaderValue.EvaluateVariable(context)!));

            return default;
        }

        public override IEnumerable<ActionExample> GetExamples()
        {
            yield return new ActionExample("Update the User-Agent header",
                new UpdateRequestHeaderAction("User-Agent", "Fluxzy"));
        }
    }
}
