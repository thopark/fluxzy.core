// Copyright 2021 - Haga Rakotoharivelo - https://github.com/haga-rak

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using Fluxzy.Rules;
using Fluxzy.Rules.Filters;
using Action = Fluxzy.Rules.Action;

namespace Fluxzy.Tools.DocGen
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var docBuilder = new DocBuilder(new DescriptionLineProvider(), new RuleConfigParser());

            var rootDirectory = new DirectoryInfo(".");

            while (rootDirectory.EnumerateFiles().All(d => d.Name != "fluxzy.core.sln")) {
                rootDirectory = rootDirectory.Parent;

                if (rootDirectory == null)
                    throw new Exception("Unable to locate fluxzy.core.sln");
            }

            var docsBaseDirectory = new DirectoryInfo(Path.Combine(rootDirectory.FullName, "docs"));

            var items = new List<SearchableItem>(); 

            BuildFilterDocs(docsBaseDirectory, docBuilder, items);
            BuildActionDocs(docsBaseDirectory, docBuilder, items);

            File.WriteAllText(Path.Combine(docsBaseDirectory.FullName, "searchable-items.json"), 
                JsonSerializer.Serialize(items, new JsonSerializerOptions(JsonSerializerDefaults.Web) {
                    WriteIndented = true
                }));

            Console.WriteLine("Done");
        }

        private static void BuildFilterDocs(DirectoryInfo docsBaseDirectory, DocBuilder docBuilder, List<SearchableItem> items)
        {
            var filterDirectory = new DirectoryInfo(Path.Combine(docsBaseDirectory.FullName, "filters"));

            if (filterDirectory.Exists)
                filterDirectory.Delete(true);

            filterDirectory.Create();

            var outDirectory = filterDirectory.FullName;

            var targets = typeof(Filter).Assembly.GetTypes()
                                        .Where(t =>
                                            t.IsSubclassOf(typeof(Filter)) &&
                                            t.GetCustomAttribute<FilterMetaDataAttribute>()?.NotSelectable == false)
                                        .ToList();

            foreach (var target in targets) {
                docBuilder.BuildFilter(outDirectory, target, items);
            }
        }

        private static void BuildActionDocs(DirectoryInfo docsBaseDirectory, DocBuilder docBuilder, List<SearchableItem> items)
        {
            var actionDirectory = new DirectoryInfo(Path.Combine(docsBaseDirectory.FullName, "actions"));

            if (actionDirectory.Exists)
                actionDirectory.Delete(true);

            actionDirectory.Create();

            var outDirectory = actionDirectory.FullName;

            var targets = typeof(Action).Assembly.GetTypes()
                                        .Where(t =>
                                            t.IsSubclassOf(typeof(Action)) &&
                                            t.GetCustomAttribute<ActionMetadataAttribute>() != null)
                                        .ToList();

            foreach (var target in targets) {
                docBuilder.BuildAction(outDirectory, target, items);
            }
        }
    }

    public class SearchableItem
    {
        public string Title { get; set; }

        public string Description { get; set; }

        public string FullTypeName { get; set; }

        public string Category { get; set; }
    }
}
