using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using MySolution.WebApi.Services.Accounts;
using MySolution.WebApi.Services.Accounts.Repositories;
using System.Text;

namespace MySolution.WebApi.Libraries.JwtTokenProvider
{
    public static class ServiceCollectionExtensions
    {
        public static AuthenticationBuilder AddJwtTokenProvider(
            this AuthenticationBuilder builder,
            Action<JwtTokenOptions> configureOptions)
        {
            ArgumentNullException.ThrowIfNull(builder, nameof(builder));

            var services = builder.Services;

            // Register strongly typed options
            services.Configure(configureOptions);

            // Register provider
            services.AddScoped<IJwtTokenProvider, DefaultJwtTokenProvider>();

            builder.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme);

            // Configure JwtBearerOptions using DI
            services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
                .Configure<IOptions<JwtTokenOptions>>((jwtOptions, tokenOptionsAccessor) =>
                {
                    var tokenOptions = tokenOptionsAccessor.Value;

                    jwtOptions.MapInboundClaims = false;
                    jwtOptions.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidIssuer = tokenOptions.Issuer,

                        ValidateAudience = true,
                        ValidAudiences = tokenOptions.Audience,

                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tokenOptions.Secret)),

                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.Zero,

                        NameClaimType = JwtRegisteredClaimNames.Sub,
                        RoleClaimType = "role",

                        ValidTypes = [JwtTokenTypes.AccessToken]
                    };

                    jwtOptions.Events = new JwtBearerEvents
                    {
                        OnAuthenticationFailed = context =>
                        {
                            var logger = context.HttpContext.RequestServices
                                .GetRequiredService<ILoggerFactory>()
                                .CreateLogger(nameof(JwtBearerEvents));

                            logger.LogError(context.Exception, "JWT authentication failed: {Message}.", context.Exception.Message);
                            return Task.CompletedTask;
                        },

                        OnTokenValidated = async context =>
                        {
                            var logger = context.HttpContext.RequestServices
                                .GetRequiredService<ILoggerFactory>()
                                .CreateLogger(nameof(JwtBearerEvents));

                            var jwtTokenProvider = context.HttpContext.RequestServices
                                .GetRequiredService<IJwtTokenProvider>();

                            var principal = context.Principal;

                            if (principal == null)
                            {
                                logger.LogWarning("Token validation failed: principal is null.");
                                context.Fail("Token validation failed: principal is null.");
                                return;
                            }

                            var subject = principal.GetSubject();

                            if (string.IsNullOrWhiteSpace(subject))
                            {
                                logger.LogWarning("Token validation failed: subject claim is missing.");
                                context.Fail("Token validation failed: subject claim is missing.");
                                return;
                            }

                            var isValid = await jwtTokenProvider.ValidateSecurityStampAsync(subject, principal, context.HttpContext.RequestAborted);

                            if (!isValid)
                            {
                                logger.LogWarning("Token validation failed: invalid security stamp for subject {Subject}.", subject);
                                context.Fail("Token validation failed: invalid security stamp.");
                            }
                        },

                        OnChallenge = context =>
                        {
                            var logger = context.HttpContext.RequestServices
                                .GetRequiredService<ILoggerFactory>()
                                .CreateLogger(nameof(JwtBearerEvents));

                            logger.LogWarning("Token challenge triggered: {Error} - {ErrorDescription}.", context.Error, context.ErrorDescription);
                            return Task.CompletedTask;
                        },
                    };
                });

            return builder;
        }
    }
}