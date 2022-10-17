﻿using System;

namespace Fluxzy.Rules.Filters.ResponseFilters
{
    public class ContentTypeXmlFilter : ResponseHeaderFilter
    {
        public override string AutoGeneratedName { get; } = "XML response only";
        
        public ContentTypeXmlFilter() : base("xml", StringSelectorOperation.Contains, "Content-Type")
        {
        }

        public override Guid Identifier => Guid.Parse("7C0474E6-925E-4179-BD21-5BEAE6B37E17");

        public override string GenericName => "XML response only";

        public override string ShortName => "xml";

        public override bool PreMadeFilter => true;
    }
}