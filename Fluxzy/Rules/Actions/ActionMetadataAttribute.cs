﻿// Copyright 2021 - Haga Rakotoharivelo - https://github.com/haga-rak

using System;

namespace Fluxzy.Rules.Actions
{
    public class ActionMetadataAttribute : Attribute
    {
        public ActionMetadataAttribute(string longDescription)
        {
            LongDescription = longDescription;
        }

        public string LongDescription { get; }
    }
}
