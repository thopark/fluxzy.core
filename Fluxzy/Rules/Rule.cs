﻿// Copyright © 2022 Haga Rakotoharivelo

using System;
using System.Threading.Tasks;
using Fluxzy.Clients;
using Fluxzy.Rules.Filters;
using YamlDotNet.Serialization;

namespace Fluxzy.Rules
{
    public class Rule
    {
        public Guid Identifier { get; set; } = Guid.NewGuid();

        public string? Name { get; set; }

        public Filter Filter { get; set; }

        public Action Action { get; set; }

        public int Order { get; set; }

        [YamlIgnore]
        public bool InScope => Filter.FilterScope <= Action.ActionScope;

        public Rule(Action action, Filter filter)
        {
            Filter = filter;
            Action = action;
        }

        public ValueTask Enforce(ExchangeContext context,
            Exchange? exchange,
            Connection? connection)
        {
            // TODO put a decent filtering context here 
            if (Filter.Apply(context.Authority, exchange, null))
                return Action.Alter(context, exchange, connection);

            return default;
        }
    }
}
