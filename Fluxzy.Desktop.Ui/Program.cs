
using Echoes.Desktop.Ui.Hubs;
using Fluxzy;
using Fluxzy.Desktop.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllersWithViews().AddJsonOptions(options =>
{
    foreach (var converter in GlobalArchiveOption.JsonSerializerOptions.Converters)
    {
        options.JsonSerializerOptions.Converters.Add(converter);
    }
});

builder.Services.AddFluxzyDesktopServices();
builder.Services.AddSignalR();

var app = builder.Build();

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller}/{action=Index}/{id?}");

app.MapHub<GlobalHub>("/global");

app.MapFallbackToFile("index.html");

var globalFileManager = app.Services.GetRequiredService<GlobalFileManager>();
//await globalFileManager.New();
await globalFileManager.Open(@"../Samples/boot.fxyz");

app.Run();