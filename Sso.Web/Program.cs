using Sso.Web;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthorization();

builder.Services.AddSingleton<TokenRefresher>();

builder.Configuration.AddJsonFile("appsettings.json", true, false)
    .AddEnvironmentVariables("SSO_PROXY");

builder.Services.AddSsoAuthentication();

WebApplication app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/weatherforecast", () => "Hey !").RequireAuthorization();

app.Run();