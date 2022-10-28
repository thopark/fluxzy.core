﻿using System.Reactive.Linq;
using Fluxzy.Desktop.Services.Filters;
using Fluxzy.Desktop.Services.Filters.Implementations;
using Fluxzy.Desktop.Services.Models;
using Fluxzy.Desktop.Services.Rules;
using Fluxzy.Formatters;
using Fluxzy.Formatters.Producers.ProducerActions.Actions;
using Fluxzy.Readers;
using Fluxzy.Rules;
using Fluxzy.Writers;
using Microsoft.Extensions.DependencyInjection;

namespace Fluxzy.Desktop.Services
{
    public static class GlobalRegistration
    {
        public static IServiceCollection AddFluxzyDesktopServices(this IServiceCollection collection)
        {
            collection.AddSingleton<FileManager>();
            collection.AddSingleton<ProxyControl>();
            collection.AddSingleton<FluxzySettingManager>();
            collection.AddSingleton<UiStateManager>();
            collection.AddSingleton<SystemProxyStateControl>();
            collection.AddSingleton<ActiveViewFilterManager>();
            collection.AddSingleton<FilteredExchangeManager>();
            collection.AddSingleton<FileContentUpdateManager>();
            collection.AddSingleton<ToolBarFilterProvider>();
            collection.AddSingleton<TemplateToolBarFilterProvider>();
            collection.AddSingleton<ForwardMessageManager>();
            collection.AddSingleton<IRuleStorage, LocalRuleStorage>();
            collection.AddSingleton<ActiveRuleManager>();

            collection.AddSingleton<IObservable<SystemProxyState>>
                (s => s.GetRequiredService<SystemProxyStateControl>().ProvidedObservable);

            collection.AddSingleton<IObservable<FileState>>
                (s => s.GetRequiredService<FileManager>().ProvidedObservable);

            collection.AddSingleton<IObservable<IArchiveReader>>
                (s => s.GetRequiredService<IObservable<FileState>>()
                       .Select(f => new DirectoryArchiveReader(f.WorkingDirectory)));

            collection.AddSingleton<IObservable<FluxzySettingsHolder>>
                (s => s.GetRequiredService<FluxzySettingManager>().ProvidedObservable);

            collection.AddSingleton<IObservable<ProxyState>>
                (s => s.GetRequiredService<ProxyControl>().ProvidedObservable);

            collection.AddSingleton<IObservable<RealtimeArchiveWriter?>>
                (s => s.GetRequiredService<ProxyControl>().WriterObservable);

            collection.AddSingleton<IObservable<ViewFilter>>
                (s => s.GetRequiredService<ActiveViewFilterManager>().ProvidedObservable);

            collection.AddSingleton<IObservable<FilteredExchangeState?>>
                (s => s.GetRequiredService<FilteredExchangeManager>().ProvidedObservable);

            collection.AddSingleton<IObservable<List<Rule>>>
                (s => s.GetRequiredService<ActiveRuleManager>().ActiveRules);

            collection.AddSingleton<IObservable<TemplateToolBarFilterModel>>
                (s => s.GetRequiredService<TemplateToolBarFilterProvider>().ProvidedObservable);

            collection.AddSingleton<IObservable<FileContentOperationManager>>
                (s => s.GetRequiredService<IObservable<FileState>>().Select(v => v.ContentOperation));

            collection.AddSingleton<IObservable<TrunkState>>
                (s => s.GetRequiredService<IObservable<FileContentOperationManager>>()
                    .Select(t => t.Observable).Switch());


            collection.AddScoped<IArchiveReaderProvider, ArchiveReaderProvider>();
            collection.AddScoped<FilterTemplateManager>();
            collection.AddScoped<ContextMenuActionProvider>();
            collection.AddScoped<ContextMenuFilterProvider>();
            collection.AddScoped<ActionTemplateManager>();

            collection.AddTransient<FxzyDirectoryPackager>();

            collection.AddTransient<ProducerSettings>(); // TODO move to hard settings 

            collection.AddFluxzyProducers();

            collection.AddViewFilters();

            return collection; 
        }

        public static IServiceCollection AddFluxzyProducers(this IServiceCollection serviceCollection)
        {
            serviceCollection.AddScoped<ProducerFactory>();
            serviceCollection.AddScoped<SaveRequestBodyProducerAction>();
            serviceCollection.AddScoped<SaveFileMultipartAction>();
            serviceCollection.AddScoped<SaveResponseBodyAction>();
            serviceCollection.AddScoped<SaveWebSocketBodyAction>();

            return serviceCollection;

        }

        public static IServiceCollection AddViewFilters(this IServiceCollection serviceCollection)
        {
            serviceCollection.AddScoped<ViewFilterManagement>();
            serviceCollection.AddSingleton<LocalFilterStorage>();
            serviceCollection.AddSingleton<InSessionFileStorage>();

            return serviceCollection;

        }
    }
}