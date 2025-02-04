using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;

namespace Sso.Web.Upstream;

public static class AuthenticationExtensions
{
    public static IServiceCollection AddSsoAuthentication(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services, nameof(services));

        ConfigureBearerOptions(services);

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer();

        services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .Configure<IOptions<BearerConfiguration>>((opts, bearerOpts) =>
            {
                BearerConfiguration bearerConfiguration = bearerOpts.Value;

                opts.Authority = bearerConfiguration.Authority;
                opts.SaveToken = false;
                opts.RequireHttpsMetadata = false;

                opts.TokenValidationParameters.ValidateAudience = false;
                opts.TokenValidationParameters.ValidateIssuer = true;
                opts.TokenValidationParameters.ValidateLifetime = true;
                opts.TokenValidationParameters.LogValidationExceptions = true;
                opts.TokenValidationParameters.ClockSkew = TimeSpan.FromSeconds(bearerConfiguration.ClockSkewSeconds);

                opts.Events = new JwtBearerEvents
                {
                    OnChallenge = context =>
                    {
                        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                        context.HandleResponse();

                        return Task.CompletedTask;
                    }
                };
            });

        return services;
    }

    private static void ConfigureBearerOptions(IServiceCollection services)
    {
        services.AddOptions<BearerConfiguration>()
            .BindConfiguration(BearerConfiguration.SectionName)
            .ValidateOnStart();
    }
}