namespace Sso.Web;

public sealed class SsoConfiguration
{
    public const string SectionName = "Sso";
    
    public required int KeycloakSsoMaxMinutes { get; init; }
    
    public required int KeycloakSsoIdleMinutes { get; init; }
    
    public required string KeycloakClientId { get; init; }
    
    public required string KeycloakClientSecret { get; init; }
    
    public required string KeycloakAuthority { get; init; }

    public required int ClockSkewSeconds { get; init; } = 45;
    
    public required int KeycloakAccessTokenLifetimeSeconds { get; init; }

    public required string CookieName { get; init; } = Guid.NewGuid().ToString("N");
}