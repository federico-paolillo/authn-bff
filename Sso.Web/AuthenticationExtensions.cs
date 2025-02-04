using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Sso.Web;

public static class AuthenticationExtensions
{
    public static IServiceCollection AddSsoAuthentication(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services, nameof(services));

        services.AddSingleton<TokenRefresher>();

        ConfigureSsoOptions(services);

        services.AddAuthentication(opts =>
            {
                opts.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                opts.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
                opts.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                opts.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
            .AddOpenIdConnect()
            .AddCookie();

        ConfigureOpenIdConnectOptions(services);
        ConfigureCookieOptions(services);

        return services;
    }

    private static void ConfigureSsoOptions(IServiceCollection services)
    {
        services.AddOptions<SsoConfiguration>()
            .BindConfiguration(SsoConfiguration.SectionName)
            .ValidateOnStart();
    }

    private static void ConfigureOpenIdConnectOptions(IServiceCollection services)
    {
        services.AddOptions<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme)
            .Configure<IOptions<SsoConfiguration>>((opts, ssoOpts) =>
            {
                SsoConfiguration ssoConfiguration = ssoOpts.Value;

                opts.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                opts.UsePkce = true;
                opts.Authority = ssoConfiguration.KeycloakAuthority;
                opts.ClientId = ssoConfiguration.KeycloakClientId;
                opts.ClientSecret = ssoConfiguration.KeycloakClientSecret;
                opts.SaveTokens = true;
                opts.AuthenticationMethod = OpenIdConnectRedirectBehavior.FormPost;
                opts.ResponseType = OpenIdConnectResponseType.Code;

                // Match Keycloak max. sso timeout
                // We know that Keycloak will expire the session after 5 mins. there is no point in attempting to reuse an older session
                opts.MaxAge = TimeSpan.FromMinutes(ssoConfiguration.KeycloakSsoMaxMinutes);

                // Ensure we allow for some leeway when checking tokens expiry to account for transport delays
                opts.TokenValidationParameters.ClockSkew = TimeSpan.FromSeconds(ssoConfiguration.ClockSkewSeconds);
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
                        context.Response.Cookies.Delete(ssoConfiguration.CookieName);
                        context.Response.Redirect(returnUrl);

                        return Task.CompletedTask;
                    }
                };
            });
    }

    private static void ConfigureCookieOptions(IServiceCollection services)
    {
        services.AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
            .Configure<TokenRefresher, IOptions<SsoConfiguration>>((opts, refresher, ssoOpts) =>
            {
                SsoConfiguration ssoConfiguration = ssoOpts.Value;

                opts.Cookie.HttpOnly = true;
                opts.Cookie.Name = ssoConfiguration.CookieName;
                opts.Cookie.SameSite = SameSiteMode.Lax;
                opts.Cookie.IsEssential = true;

                // Match Keycloak max. sso
                // There is no point in keeping this Cookie around longer than Keycloak SSO max. session
                opts.Cookie.MaxAge = TimeSpan.FromMinutes(ssoConfiguration.KeycloakSsoMaxMinutes);

                // Match Keycloak idle timeout
                // There is no point in keeping the authn. ticket longer than Keycloak SSO session idle
                opts.ExpireTimeSpan = TimeSpan.FromMinutes(ssoConfiguration.KeycloakSsoIdleMinutes);
                opts.SlidingExpiration = true;

                opts.Events.OnRedirectToLogin = ctx =>
                {
                    // When the Token refresher rejects the principal (when refreshing tokens fails) we take care of cleaning up Cookies with expired tokens
                    // Cookies may have not expired but the tokens within them are in fact expired so we clean up to avoid confusing the authn. handler
                    ctx.Response.Cookies.Delete(ssoConfiguration.CookieName);

                    return Task.CompletedTask;
                };

                opts.Events.OnValidatePrincipal = ctx =>
                {
                    return refresher.ValidateOrRefreshCookieAsync(ctx, OpenIdConnectDefaults.AuthenticationScheme);
                };
            });
    }
}