using Sso.Web.Upstream;

WebApplicationBuilder? builder = WebApplication.CreateBuilder(args);

builder.Services.AddSsoAuthentication();
builder.Services.AddAuthorization();

WebApplication? app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => Results.Text("Hello World")).RequireAuthorization();

app.Run();