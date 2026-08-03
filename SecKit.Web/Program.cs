using SecKit.Web.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();

// Register SecKit services
builder.Services.AddSingleton<SecKit.Core.ConfigManager>(sp =>
    new SecKit.Core.ConfigManager(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "appsettings.json")));
builder.Services.AddSingleton<ScanService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseStaticFiles();
app.UseRouting();
app.MapBlazorHub();
app.MapFallbackToPage("/_Host");

app.Run();
