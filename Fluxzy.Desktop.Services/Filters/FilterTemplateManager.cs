﻿// Copyright © 2022 Haga RAKOTOHARIVELO

using System.Reflection;
using Fluxzy.Rules.Filters;

namespace Fluxzy.Desktop.Services.Filters
{
    public class FilterTemplateManager
    {
        private static readonly List<TypeFilter> TypeFilters;
        private static readonly List<Filter> DefaultTemplates = new();
        private static readonly Dictionary<Type, Filter> Instances = new();
        private static readonly Dictionary<string, FilterMetaDataAttribute> DescriptionMapping = new();

        static FilterTemplateManager()
        {
            TypeFilters = typeof(Filter).Assembly.GetTypes()
                                        .Where(derivedType => typeof(Filter).IsAssignableFrom(derivedType)
                                                              && derivedType.IsClass
                                                              && !derivedType.IsAbstract)
                                        .Where(derivedType =>
                                            derivedType.GetCustomAttribute<FilterMetaDataAttribute>() != null)
                                        // TODO : update this suboptimal double call of GetCustomAttribute
                                        .Select(derivedType => new TypeFilter(derivedType,
                                            derivedType.GetCustomAttribute<FilterMetaDataAttribute>()!))
                                        .ToList();

            foreach (var item in TypeFilters)
            {
                var filter = CreateFilter(item);
                Instances[item.Type] = filter;
                DefaultTemplates.Add(filter);
                DescriptionMapping[filter.TypeKind] = item.MetaData;
            }

            DefaultTemplates = DefaultTemplates.OrderBy(t => t.AutoGeneratedName).ToList();
        }

        private static Filter CreateFilter(TypeFilter item)
        {
            var constructor = item.Type.GetConstructors()
                                  .OrderByDescending(t => t.GetParameters().Length).First();

            var arguments = new List<object>();

            foreach (var argument in constructor.GetParameters())
                arguments.Add(argument.ParameterType == typeof(string)
                    ? string.Empty
                    : ReflectionHelper.GetDefault(argument.ParameterType));

            var filter = (Filter)constructor.Invoke(arguments.ToArray());

            return filter;
        }

        // TODO load this by reflection
        public List<FilterTemplate> ReadAvailableTemplates()
        {
            var res = DefaultTemplates.Select(f => new FilterTemplate(f)).ToList();

            return res;
        }

        public bool TryGetDescription(string typeKind, out string longDescription)
        {
            if (DescriptionMapping.TryGetValue(typeKind, out var metaData))
            {
                longDescription = metaData.LongDescription ?? string.Empty;

                return true;
            }

            longDescription = string.Empty;

            return false;
        }

        private class TypeFilter
        {
            public Type Type { get; }

            public FilterMetaDataAttribute MetaData { get; }

            public TypeFilter(Type type, FilterMetaDataAttribute metaData)
            {
                Type = type;
                MetaData = metaData;
            }
        }
    }

    internal static class ReflectionHelper
    {
        public static object GetDefault(Type t)
        {
            return typeof(ReflectionHelper)
                   .GetMethod(nameof(GetDefaultGeneric), BindingFlags.Static | BindingFlags.Public)!
                   .MakeGenericMethod(t).Invoke(null, null)!;
        }

        public static T? GetDefaultGeneric<T>()
        {
            return default;
        }
    }
}
