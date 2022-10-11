﻿// Copyright © 2022 Haga Rakotoharivelo

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;

namespace Fluxzy.Rules.Filters
{
    public abstract class StringFilter : Filter
    {
        protected StringFilter(string pattern)
            : this (pattern, StringSelectorOperation.Contains)
        {
        }

        protected StringFilter(string pattern, StringSelectorOperation operation)
        {
            Pattern = pattern;
            Operation = operation;
        }

        protected override bool InternalApply(IAuthority authority, IExchange exchange)
        {
            var inputList = GetMatchInputs(authority, exchange);

            var comparisonType = CaseSensitive ? StringComparison.InvariantCulture :
                StringComparison.InvariantCultureIgnoreCase;

            foreach (var input in inputList)
            {
                switch (Operation)
                {
                    case StringSelectorOperation.Exact:
                        if (Pattern.Equals(input, comparisonType))
                            return true;
                        continue; 
                    case StringSelectorOperation.Contains:
                        if (input.Contains(Pattern, comparisonType))
                            return true;
                        continue;
                    case StringSelectorOperation.StartsWith:
                        if (input.StartsWith(Pattern, comparisonType))
                            return true;
                        continue;
                    case StringSelectorOperation.EndsWith:
                        if (input.EndsWith(Pattern, comparisonType))
                            return true;
                        continue;
                    case StringSelectorOperation.Regex:
                        if (Regex.Match(input, Pattern, CaseSensitive ? RegexOptions.None : RegexOptions.IgnoreCase).Success)
                            return true;
                        continue;
                    default:
                        throw new InvalidOperationException($"Unimplemented string operation {Operation}");
                }
            }

            return false; 
        }
        
        protected abstract IEnumerable<string> GetMatchInputs(IAuthority authority, IExchange exchange);

        public string Pattern { get; set; }

        public StringSelectorOperation Operation { get; set; } = StringSelectorOperation.Exact;

        public bool CaseSensitive { get; set; }
        
        public override string FriendlyName => $"{Operation.GetDescription()} : `{Pattern}`";
    }

    public enum SelectorCollectionOperation
    {
        Or,
        And
    }

    public enum StringSelectorOperation
    {
        [Description("equals")]
        Exact = 1,

        [Description("contains")]
        Contains,

        [Description("starts with")]
        StartsWith,

        [Description("ends with")]
        EndsWith,

        [Description("matchs (regex)")]
        Regex,
    }

    public static class GenericDescriptionExtension
    {
        public static string GetDescription<T>(this T enumerationValue)
            where T : struct
        {
            var type = typeof(T);

            if (!type.IsEnum)
                throw new ArgumentException($"{nameof(enumerationValue)} must be an enum");
            
            var memberInfos = type.GetMember(enumerationValue.ToString());

            if (memberInfos.Any())
            {
               var attr = memberInfos.First()
                   .GetCustomAttributes<DescriptionAttribute>(false)
                   .FirstOrDefault();

                if (attr != null)
                {
                    return attr.Description;
                }
            }

            return enumerationValue.ToString();
        }
    }
}