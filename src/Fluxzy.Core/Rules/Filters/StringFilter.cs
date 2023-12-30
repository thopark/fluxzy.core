// Copyright 2021 - Haga Rakotoharivelo - https://github.com/haga-rak

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Reflection;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Fluxzy.Core;

namespace Fluxzy.Rules.Filters
{
    public abstract class StringFilter : Filter
    {
        protected StringFilter(string pattern)
            : this(pattern, StringSelectorOperation.Contains)
        {
            // 
        }

        protected StringFilter(string pattern, StringSelectorOperation operation)
        {
            Pattern = pattern;
            Operation = operation;
        }

        [FilterDistinctive(Description = "The string pattern to search")]
        public string Pattern { get; set; }

        [FilterDistinctive(Description = "The search operation performed")]
        public StringSelectorOperation Operation { get; set; } = StringSelectorOperation.Exact;

        [FilterDistinctive(Description = "true if the Search should be case sensitive")]
        public bool CaseSensitive { get; set; }

        public override string AutoGeneratedName => $"{Operation.GetDescription()} : `{Pattern}`";

        protected override bool InternalApply(
            ExchangeContext? exchangeContext, IAuthority authority, IExchange? exchange,
            IFilteringContext? filteringContext)
        {
            var inputList = GetMatchInputs(exchangeContext, authority, exchange);

            var comparisonType = CaseSensitive
                ? StringComparison.InvariantCulture
                : StringComparison.InvariantCultureIgnoreCase;

            var pattern = Pattern.EvaluateVariable(exchangeContext)!;

            foreach (var input in inputList) {
                switch (Operation) {
                    case StringSelectorOperation.Exact:
                        if (pattern.Equals(input, comparisonType))
                            return true;

                        continue;

                    case StringSelectorOperation.Contains:
                        if (input.Contains(pattern, comparisonType))
                            return true;

                        continue;

                    case StringSelectorOperation.StartsWith:
                        if (input.StartsWith(pattern, comparisonType))
                            return true;

                        continue;

                    case StringSelectorOperation.EndsWith:
                        if (input.EndsWith(pattern, comparisonType))
                            return true;

                        continue;

                    case StringSelectorOperation.Regex:

                        if (pattern.AsSpan().DoesNotContainsCapturedRegex()) {
                            if (Regex.Match(input, pattern, CaseSensitive ? RegexOptions.None : RegexOptions.IgnoreCase)
                                     .Success)
                                return true;
                        }
                        else {
                            var multiMatch =
                                Regex.Matches(input, pattern,
                                    CaseSensitive ? RegexOptions.None : RegexOptions.IgnoreCase);

                            if (multiMatch.Any(g => g.Success)) {
                                var matchedVariable = multiMatch
                                                      .SelectMany(s => s.Groups.OfType<Group>())
                                                      .Where(g => g.Name != "0"
                                                                  && g.Success && !string.IsNullOrWhiteSpace(g.Name));

                                if (exchangeContext != null) {
                                    // If variable are present we update it

                                    foreach (var kp in matchedVariable) {
                                        exchangeContext.VariableContext.Set($"user.{kp.Name}", kp.Value);
                                    }
                                }

                                return true;
                            }
                        }

                        continue;

                    default:
                        throw new InvalidOperationException($"Unimplemented string operation {Operation}");
                }
            }

            return false;
        }

        protected abstract IEnumerable<string> GetMatchInputs(
            ExchangeContext? exchangeContext, IAuthority authority, IExchange? exchange);
    }

    [JsonConverter(typeof(JsonStringEnumConverter<SelectorCollectionOperation>))]
    public enum SelectorCollectionOperation
    {
        Or,
        And
    }

    [JsonConverter(typeof(JsonStringEnumConverter<StringSelectorOperation>))]
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
        Regex
    }

    internal static class GenericDescriptionExtension
    {
        public static string GetDescription(this StringSelectorOperation enumerationValue)
        {
            switch (enumerationValue) {
                case StringSelectorOperation.Exact:
                    return "equals";
                case StringSelectorOperation.Contains:
                     return "contains";
                case StringSelectorOperation.StartsWith:
                    return "starts with";
                case StringSelectorOperation.EndsWith:
                    return "ends with";
                case StringSelectorOperation.Regex:
                    return "matchs (regex)";
            }

            return string.Empty;
        }
    }
}
