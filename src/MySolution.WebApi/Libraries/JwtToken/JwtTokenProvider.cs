using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MySolution.WebApi.Data;
using MySolution.WebApi.Helpers;
using MySolution.WebApi.Libraries.Globalizer;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace MySolution.WebApi.Libraries.JwtToken
{
    public class JwtTokenProvider : IJwtTokenProvider
    {
        private readonly JwtTokenOptions _options;
        private readonly DefaultDbContext _dbContext;
        private readonly ILogger<JwtTokenProvider> _logger;
        private readonly IGlobalizer _globalizer;

        public JwtTokenProvider(
            IOptions<JwtTokenOptions> options,
            DefaultDbContext dbContext,
            ILogger<JwtTokenProvider> logger,
            IGlobalizer globalizer)
        {
            _options = options.Value;
            _dbContext = dbContext;
            _logger = logger;
            _globalizer = globalizer;
        }

        public async Task<JwtRawToken> CreateTokenAsync(string subject, IEnumerable<Claim>? claims = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(subject, nameof(subject));

            var currentTime = _globalizer.Time.GetUtcNow();
            var accessTokenExpiresAt = currentTime.Add(_options.AccessTokenExpiresIn);
            var refreshTokenExpiresAt = currentTime.Add(_options.RefreshTokenExpiresIn);

            var accessToken = GenerateToken(subject, currentTime, accessTokenExpiresAt, JwtTokenTypes.AccessToken, claims);
            var refreshToken = GenerateToken(subject, currentTime, refreshTokenExpiresAt, JwtTokenTypes.RefreshToken, null);

            var tokenEntity = new JwtToken
            {
                Id = Guid.NewGuid(),
                Subject = subject,
                IssuedAt = currentTime,
                AccessTokenHash = HashHelper.HashInput(accessToken),
                AccessTokenExpiresAt = accessTokenExpiresAt,
                RefreshTokenHash = HashHelper.HashInput(refreshToken),
                RefreshTokenExpiresAt = refreshTokenExpiresAt
            };

            _dbContext.Set<JwtToken>().Add(tokenEntity);
            await _dbContext.SaveChangesAsync(cancellationToken);

            return new JwtRawToken
            {
                AccessToken = accessToken,
                AccessTokenExpiresAt = accessTokenExpiresAt,
                RefreshToken = refreshToken,
                RefreshTokenExpiresAt = refreshTokenExpiresAt
            };
        }

        public async Task RevokeAllTokensAsync(string subject, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(subject, nameof(subject));

            var tokens = await _dbContext.Set<JwtToken>()
                .Where(t => t.Subject == subject)
                .ToListAsync(cancellationToken);

            _dbContext.Set<JwtToken>().RemoveRange(tokens);
            await _dbContext.SaveChangesAsync(cancellationToken);
        }

        public async Task RevokeExpiredTokensAsync(string subject, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(subject, nameof(subject));

            var currentTime = _globalizer.Time.GetUtcNow();
            // Delete fully expired tokens
            var fullyExpiredTokens = await _dbContext.Set<JwtToken>()
                .Where(t => t.Subject == subject &&
                           t.AccessTokenExpiresAt < currentTime &&
                           t.RefreshTokenExpiresAt < currentTime)
                .ToListAsync(cancellationToken);

            _dbContext.Set<JwtToken>().RemoveRange(fullyExpiredTokens);

            await _dbContext.SaveChangesAsync(cancellationToken);
        }

        public async Task RevokeTokenAsync(string subject, string tokenString, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(subject, nameof(subject));
            ArgumentNullException.ThrowIfNull(tokenString, nameof(tokenString));

            var currentTime = _globalizer.Time.GetUtcNow();

            // Delete fully expired tokens
            var fullyExpiredTokens = await _dbContext.Set<JwtToken>()
                .Where(t => t.Subject == subject &&
                           t.AccessTokenExpiresAt < currentTime &&
                           t.RefreshTokenExpiresAt < currentTime)
                .ToListAsync(cancellationToken);

            _dbContext.Set<JwtToken>().RemoveRange(fullyExpiredTokens);

            // If tokenString provided, revoke that specific token
            if (!string.IsNullOrWhiteSpace(tokenString))
            {
                var tokenHash = HashHelper.HashInput(tokenString);

                if (!string.IsNullOrWhiteSpace(tokenHash))
                {
                    var tokenToRevoke = await _dbContext.Set<JwtToken>()
                        .Where(t => t.Subject == subject &&
                                   (t.AccessTokenHash == tokenHash || t.RefreshTokenHash == tokenHash))
                        .FirstOrDefaultAsync(cancellationToken);

                    if (tokenToRevoke != null)
                    {
                        _dbContext.Set<JwtToken>().Remove(tokenToRevoke);
                    }
                }
            }

            await _dbContext.SaveChangesAsync(cancellationToken);
        }

        public async Task<ClaimsPrincipal?> ValidateAccessTokenAsync(string tokenString, CancellationToken cancellationToken = default)
        {
            return await ValidateTokenAsync(JwtTokenTypes.AccessToken, tokenString, cancellationToken);
        }

        public async Task<ClaimsPrincipal?> ValidateRefreshTokenAsync(string tokenString, CancellationToken cancellationToken = default)
        {
            return await ValidateTokenAsync(JwtTokenTypes.RefreshToken, tokenString, cancellationToken);
        }

        private async Task<ClaimsPrincipal?> ValidateTokenAsync(string tokenType, string tokenString, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(tokenType, nameof(tokenType));
            ArgumentNullException.ThrowIfNull(tokenString, nameof(tokenString));

            if (!JwtTokenTypes.AllTypes.Contains(tokenType, StringComparer.InvariantCulture))
                throw new ArgumentException($"Invalid token type '{tokenType}'.", nameof(tokenType));

            try
            {
                _logger.LogInformation("Validating {TokenType} token...", tokenType);

                var tokenHandler = new JwtSecurityTokenHandler();
                tokenHandler.MapInboundClaims = false;

                var key = Encoding.UTF8.GetBytes(_options.Secret);

                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = !string.IsNullOrWhiteSpace(_options.Issuer),
                    ValidIssuer = _options.Issuer,

                    ValidateAudience = _options.Audience.Any(),
                    ValidAudiences = _options.Audience,

                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),

                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero,

                    ValidTypes = [tokenType],

                    NameClaimType = JwtRegisteredClaimNames.Sub,
                    RoleClaimType = "role",
                };

                var principal = tokenHandler.ValidateToken(tokenString, validationParameters, out var validatedToken);

                if (validatedToken is not JwtSecurityToken jwtToken)
                {
                    _logger.LogWarning("Token validation failed: not a valid JWT.");
                    return null;
                }

                var subject = jwtToken.Subject;

                if (string.IsNullOrWhiteSpace(subject))
                {
                    _logger.LogWarning("Token validation failed: subject (sub) claim missing.");
                    return null;
                }

                _logger.LogInformation("Token subject: {Subject}", subject);

                // Validate token against database
                if (!await ValidateTokenInDatabaseAsync(subject, tokenString, tokenType, cancellationToken))
                {
                    _logger.LogWarning(
                        "Token validation failed: token not found in database (subject: {Subject}).",
                        subject);

                    return null;
                }

                _logger.LogInformation("Token validation succeeded for subject: {Subject}.", subject);

                return principal;
            }
            catch (SecurityTokenException ex)
            {
                _logger.LogWarning(ex, "Token security validation failed.");
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during token validation.");
                return null;
            }
        }

        private async Task<bool> ValidateTokenInDatabaseAsync(string subject, string tokenString, string tokenType, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(subject, nameof(subject));
            ArgumentNullException.ThrowIfNull(tokenType, nameof(tokenType));
            ArgumentNullException.ThrowIfNull(tokenString, nameof(tokenString));

            if (!JwtTokenTypes.AllTypes.Contains(tokenType, StringComparer.InvariantCulture))
                throw new ArgumentException($"Invalid token type '{tokenType}'.", nameof(tokenType));

            var tokenHash = HashHelper.HashInput(tokenString);
            var currentTime = _globalizer.Time.GetUtcNow();

            var query = _dbContext.Set<JwtToken>().Where(t => t.Subject == subject);

            if (tokenType == JwtTokenTypes.AccessToken)
            {
                query = query.Where(t => t.AccessTokenHash == tokenHash &&
                                        t.AccessTokenExpiresAt > currentTime);
            }
            else
            {
                query = query.Where(t => t.RefreshTokenHash == tokenHash &&
                                        t.RefreshTokenExpiresAt > currentTime);
            }

            var tokenExists = await query.AnyAsync(cancellationToken);
            return tokenExists;
        }

        private string GenerateToken(string subject, DateTimeOffset issuedAt, DateTimeOffset expiresAt, string tokenType, IEnumerable<Claim>? additionalClaims)
        {
            ArgumentNullException.ThrowIfNull(tokenType, nameof(tokenType));

            if (!JwtTokenTypes.AllTypes.Contains(tokenType, StringComparer.InvariantCulture))
                throw new ArgumentException($"Invalid token type '{tokenType}'.", nameof(tokenType));

            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, subject),
                new(JwtRegisteredClaimNames.Iat, issuedAt.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new(JwtRegisteredClaimNames.Typ, tokenType)
            };

            if (!string.IsNullOrWhiteSpace(_options.Issuer))
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.Iss, _options.Issuer));
            }

            foreach (var aud in _options.Audience)
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.Aud, aud));
            }

            // Add additional claims if provided
            if (additionalClaims != null)
            {
                claims.AddRange(additionalClaims);
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.Secret));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _options.Issuer,
                claims: claims,
                expires: expiresAt.UtcDateTime,
                notBefore: issuedAt.UtcDateTime,
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }

    public interface IJwtTokenProvider
    {
        Task<JwtRawToken> CreateTokenAsync(string subject, IEnumerable<Claim>? claims = null, CancellationToken cancellationToken = default);
        Task RevokeAllTokensAsync(string subject, CancellationToken cancellationToken = default);
        Task RevokeExpiredTokensAsync(string subject, CancellationToken cancellationToken = default);
        Task RevokeTokenAsync(string subject, string tokenString, CancellationToken cancellationToken = default);
        Task<ClaimsPrincipal?> ValidateAccessTokenAsync(string tokenString, CancellationToken cancellationToken = default);
        Task<ClaimsPrincipal?> ValidateRefreshTokenAsync(string tokenString, CancellationToken cancellationToken = default);
    }

    public static class JwtTokenTypes
    {
        public const string AccessToken = "at+jwt";
        public const string RefreshToken = "rt+jwt";

        public static readonly string[] AllTypes = [AccessToken, RefreshToken];
    }
}