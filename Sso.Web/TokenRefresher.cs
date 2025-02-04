using System.Globalization;
using System.Security.Claims;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Sso.Web;

// https://github.com/dotnet/aspnetcore/issues/8175
internal sealed class TokenRefresher(
    IOptionsMonitor<OpenIdConnectOptions> oidcOptionsMonitor,
    IOptions<SsoConfiguration> ssoConfigurationOptions)
{
    private const double LifetimeTouseBeforeRefreshPercentage = 0.7;

    public async Task ValidateOrRefreshCookieAsync(CookieValidatePrincipalContext validateContext, string oidcScheme)
    {
        string? accessTokenExpirationText = validateContext.Properties.GetTokenValue("expires_at");
        if (!DateTimeOffset.TryParse(accessTokenExpirationText, out DateTimeOffset accessTokenExpiration))
        {
            return;
        }

        int tokenTotalLifetime = ssoConfigurationOptions.Value.KeycloakAccessTokenLifetimeSeconds;
        double tokenLifetimeToUseBeforeRefreshInSeconds = tokenTotalLifetime * LifetimeTouseBeforeRefreshPercentage;

        OpenIdConnectOptions oidcOptions = oidcOptionsMonitor.Get(oidcScheme);
        DateTimeOffset now = oidcOptions.TimeProvider!.GetUtcNow();
        if (now + TimeSpan.FromSeconds(tokenLifetimeToUseBeforeRefreshInSeconds) < accessTokenExpiration)
        {
            return;
        }

        OpenIdConnectConfiguration? oidcConfiguration =
            await oidcOptions.ConfigurationManager!.GetConfigurationAsync(validateContext.HttpContext.RequestAborted);
        string tokenEndpoint = oidcConfiguration.TokenEndpoint ??
                               throw new InvalidOperationException("Cannot refresh cookie. TokenEndpoint missing!");

        using HttpResponseMessage refreshResponse = await oidcOptions.Backchannel.PostAsync(tokenEndpoint,
            new FormUrlEncodedContent(new Dictionary<string, string?>
            {
                ["grant_type"] = "refresh_token",
                ["client_id"] = oidcOptions.ClientId,
                ["client_secret"] = oidcOptions.ClientSecret,
                // ["scope"] = string.Join(" ", oidcOptions.Scope), This is not needed for Keycloak
                ["refresh_token"] = validateContext.Properties.GetTokenValue("refresh_token")
            }));

        if (refreshResponse.IsSuccessStatusCode is false)
        {
            validateContext.RejectPrincipal();
            return;
        }

        string refreshJson = await refreshResponse.Content.ReadAsStringAsync();
        OpenIdConnectMessage message = new(refreshJson);

        TokenValidationParameters? validationParameters = oidcOptions.TokenValidationParameters.Clone();

        validationParameters.ValidIssuer = oidcConfiguration.Issuer;
        validationParameters.IssuerSigningKeys = oidcConfiguration.SigningKeys;

        TokenValidationResult? validationResult =
            await oidcOptions.TokenHandler.ValidateTokenAsync(message.IdToken, validationParameters);

        if (validationResult.IsValid is false)
        {
            validateContext.RejectPrincipal();
            return;
        }

        validateContext.ShouldRenew = true;
        validateContext.ReplacePrincipal(new ClaimsPrincipal(validationResult.ClaimsIdentity));

        int expiresIn = int.Parse(message.ExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture);
        DateTimeOffset expiresAt = now + TimeSpan.FromSeconds(expiresIn);

        validateContext.Properties.StoreTokens([
            new AuthenticationToken { Name = "access_token", Value = message.AccessToken },
            new AuthenticationToken { Name = "id_token", Value = message.IdToken },
            new AuthenticationToken { Name = "refresh_token", Value = message.RefreshToken },
            new AuthenticationToken { Name = "token_type", Value = message.TokenType },
            new AuthenticationToken
            {
                Name = "expires_at", Value = expiresAt.ToString("o", CultureInfo.InvariantCulture)
            }
        ]);
    }
}