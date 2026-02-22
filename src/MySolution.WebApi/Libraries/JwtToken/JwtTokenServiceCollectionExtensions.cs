using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using MySolution.WebApi.Services.Identity;
using MySolution.WebApi.Services.Identity.Repositories;
using System.Text;

namespace MySolution.WebApi.Libraries.JwtToken
{
    public static class JwtTokenServiceCollectionExtensions
    {
        public static AuthenticationBuilder AddJwt(
            this AuthenticationBuilder builder,
            Action<JwtTokenOptions> configureOptions)
        {
            var services = builder.Services;

            // Register strongly typed options
            services.Configure(configureOptions);

            // Register provider
            services.AddScoped<IJwtTokenProvider, JwtTokenProvider>();

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
                        IssuerSigningKey =
                            new SymmetricSecurityKey(
                                Encoding.UTF8.GetBytes(tokenOptions.Secret)
                            ),

                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.Zero
                    };

                    jwtOptions.Events = new JwtBearerEvents
                    {
                        OnAuthenticationFailed = context =>
                        {
                            var logger = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger(nameof(JwtBearerEvents));
                            logger.LogError(context.Exception, $"JWT Authentication failed.");
                            return Task.CompletedTask;
                        },
                        OnTokenValidated = async context =>
                        {
                            var logger = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger(nameof(JwtBearerEvents));
                            var userRepository = context.HttpContext.RequestServices.GetRequiredService<IUserRepository>();
                            var jwtTokenProvider = context.HttpContext.RequestServices.GetRequiredService<IJwtTokenProvider>();
                            var claimsPrincipal = context.Principal;

                            if (claimsPrincipal?.Claims == null || !claimsPrincipal.Claims.Any())
                            {
                                logger.LogWarning("Token validation failed: no claims found in the token.");
                                context.Fail("This is not our issued token. It has no claims.");
                                return;
                            }

                            var userId = claimsPrincipal.GetUserId();
                            var user = userId.HasValue ? await userRepository.GetByIdAsync(userId.Value) : null;
                            if (user == null)
                            {
                                logger.LogWarning("Token validation failed: user with ID '{UserId}' was not found.", userId);
                                context.Fail("This is not our issued token. It has no claims.");
                                return;
                            }

                            if (!claimsPrincipal.ValidateIdentity(user))
                            {
                                logger.LogWarning("Token validation failed: claims do not match the identity of user with ID '{UserId}'.", userId);
                                context.Fail("This is not our issued token. It has no claims.");
                                return;
                            }

                            if (context.SecurityToken is not JsonWebToken accessToken
                            || string.IsNullOrWhiteSpace(accessToken.EncodedToken)
                            || (await jwtTokenProvider.ValidateAccessTokenAsync(accessToken.EncodedToken) != null))
                            {
                                logger.LogWarning("Token validation failed: the access token is invalid, missing, or has been revoked.");
                                context.Fail("Invalid or missing token in the request.");
                                return;
                            }
                        },
                        OnMessageReceived = context =>
                        {
                            var accessToken = context.Request.Query["access_token"];
                            var path = context.HttpContext.Request.Path;

                            if (!string.IsNullOrEmpty(accessToken) && path.StartsWithSegments("/signalr"))
                            {
                                context.Token = accessToken;
                            }

                            return Task.CompletedTask;
                        },
                        OnChallenge = context =>
                        {
                            var logger = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger(nameof(JwtBearerEvents));
                            logger.LogError($"OnChallenge error {context.Error}, {context.ErrorDescription}");
                            return Task.CompletedTask;
                        },
                    };
                });

            return builder;
        }
    }
}