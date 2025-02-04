using Microsoft.AspNetCore.Authentication;
using Microsoft.Net.Http.Headers;

using Sso.Web;

using Yarp.ReverseProxy.Transforms;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Configuration.AddJsonFile("appsettings.json", true, false)
    .AddEnvironmentVariables("SSO_PROXY");

builder.Services.AddSsoAuthentication();
builder.Services.AddAuthorization();

IConfigurationSection rvProxyConfiguration = builder.Configuration.GetSection("ReverseProxy");

builder.Services.AddReverseProxy()
    .LoadFromConfig(rvProxyConfiguration)
    .AddTransforms(ctx =>
    {
        ctx.AddRequestTransform(async rqCtx =>
        {
            string? accessToken = await rqCtx.HttpContext.GetTokenAsync("access_token");

            // Potentially the access_token may have expired. Do we handle the 401 and add authn. Challenge ?

            rqCtx.ProxyRequest.Headers.Add(HeaderNames.Authorization, $"Bearer {accessToken}");
        });
    });

WebApplication app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapReverseProxy()
    .RequireAuthorization();

app.Run();