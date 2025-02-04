namespace Sso.Web.Upstream;

public sealed class BearerConfiguration
{
    public const string SectionName = "Bearer";

    public string Authority { get; init; }

    public required int ClockSkewSeconds { get; init; } = 45;
}