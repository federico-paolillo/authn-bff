using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

using Sso.Web;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddAuthorization();

builder.Services.AddSingleton<TokenRefresher>();

// SSO Cookie Name is not deterministic. This won't stick with multiple replicas

string ssoCookieName = Guid.NewGuid().ToString("N");

builder.Services.AddAuthentication(opts =>
    {
        opts.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        opts.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
        opts.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        opts.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    })
    .AddOpenIdConnect(opts =>
    {
        opts.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        opts.UsePkce = true;
        opts.Authority = "http://localhost:8080/realms/sso";
        opts.ClientId = "gateway";
        opts.ClientSecret = "dD4ASJKWT4WICVSWvXAaNpAYY2iROsdL";
        opts.SaveTokens = true;
        opts.AuthenticationMethod = OpenIdConnectRedirectBehavior.FormPost;
        opts.ResponseType = OpenIdConnectResponseType.Code;

        // Match Keycloak max. sso timeout
        // We know that Keycloak will expire the session after 5 mins. there is no point in attempting to reuse an older session
        opts.MaxAge = TimeSpan.FromMinutes(5);

        // Ensure we allow for some leeway when checking tokens expiry to account for transport delays
        opts.TokenValidationParameters.ClockSkew = TimeSpan.FromSeconds(45);
        opts.TokenValidationParameters.ValidateLifetime = true;

        opts.Scope.Clear();
        opts.Scope.Add(OpenIdConnectScope.OpenId);
        // Do not request offline_access. It is for something else. Refresh tokens are always issued

        opts.RequireHttpsMetadata = false;

        // It would make cookies match the "exp" of access_token. This is partially correct.
        // As Keycloak has max. sso timeouts we might have valid cookies that reference an expired refresh_token
        opts.UseTokenLifetime = false;

        opts.Events = new OpenIdConnectEvents
        {
            OnAuthenticationFailed = context =>
            {
                // This happens when:
                // - Keycloak Max. SSO or Idle SSO is reached and we have a cookie with expired refresh_token
                // - Somebody else has used the refresh_token (when Token Max. Reuse is 1) before us
                // - refresh_token is actually expired because the User did not interact with us for a while
                // This will not occur when:
                // - Access tokens expire and we detect it. Because access tokens are refresh proactively by TokenRefresher
                if (context.Exception is not SecurityTokenExpiredException)
                {
                    return Task.CompletedTask;
                }

                // We remember were we wanted to go and redirect the User there.
                // Given that the User is not authenticated at this point, this redirect will trigger a Challenge and prompt login
                string returnUrl = context.Request.Path + context.Request.QueryString;

                context.HandleResponse();

                // To ensure that the User does not send still valid Cookies (as they have a separate lifetime than tokens) with invalid Tokens contents
                // Not clearing them might trick the Oidc Authn. handler to consume expired tokens
                context.Response.Cookies.Delete(ssoCookieName);
                context.Response.Redirect(returnUrl);

                return Task.CompletedTask;
            }
        };
    })
    .AddCookie(opts =>
    {
        opts.Cookie.HttpOnly = true;
        opts.Cookie.Name = ssoCookieName;
        opts.Cookie.SameSite = SameSiteMode.Lax;
        opts.Cookie.IsEssential = true;

        // Match Keycloak max. sso
        // There is no point in keeping this Cookie around longer than Keycloak SSO max. session
        opts.Cookie.MaxAge = TimeSpan.FromMinutes(5);

        // Match Keycloak idle timeout
        // There is no point in keeping the authn. ticket longer than Keycloak SSO session idle
        opts.ExpireTimeSpan = TimeSpan.FromMinutes(1);
        opts.SlidingExpiration = true;

        opts.Events.OnRedirectToLogin = ctx =>
        {
            // When the Token refresher rejects the principal (when refreshing tokens fails) we take care of cleaning up Cookies with expired tokens
            // Cookies may have not expired but the tokens within them are in fact expired so we clean up to avoid confusing the authn. handler
            ctx.Response.Cookies.Delete(ssoCookieName);

            return Task.CompletedTask;
        };
    });

builder.Services.AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
    .Configure<TokenRefresher>((opts, refresher) =>
    {
        opts.Events.OnValidatePrincipal = context =>
            refresher.ValidateOrRefreshCookieAsync(context, OpenIdConnectDefaults.AuthenticationScheme);
    });

WebApplication app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/weatherforecast", () => "Hey !").RequireAuthorization();

app.Run();