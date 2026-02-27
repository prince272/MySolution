using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MySolution.WebApi.Data;
using MySolution.WebApi.Helpers;
using MySolution.WebApi.Libraries.CacheProvider;
using MySolution.WebApi.Libraries.Globalizer;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace MySolution.WebApi.Libraries.JwtTokenProvider
{
    public class DefaultJwtTokenProvider : IJwtTokenProvider
    {
        private const string SecurityStampClaimType = "security_stamp";

        private readonly JwtTokenOptions _options;
        private readonly DefaultDbContext _dbContext;
        private readonly ILogger<DefaultJwtTokenProvider> _logger;
        private readonly IGlobalizer _globalizer;
        private readonly ICacheProvider _cacheProvider;

        public DefaultJwtTokenProvider(
            IOptions<JwtTokenOptions> options,
            DefaultDbContext dbContext,
            ILogger<DefaultJwtTokenProvider> logger,
            IGlobalizer globalizer,
            ICacheProvider cacheProvider)
        {
            _options = options.Value;
            _dbContext = dbContext;
            _logger = logger;
            _globalizer = globalizer;
            _cacheProvider = cacheProvider;
        }

        public async Task<JwtRawToken> CreateTokenAsync(string subject, IEnumerable<Claim>? claims = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(subject, nameof(subject));

            var currentTime = _globalizer.Time.GetUtcNow();
            var accessTokenExpiresAt = currentTime.Add(_options.AccessTokenExpiresIn);
            var refreshTokenExpiresAt = currentTime.Add(_options.RefreshTokenExpiresIn);

            var securityStamp = await GetOrCreateSecurityStampAsync(subject, cancellationToken);

            var accessToken = GenerateToken(subject, securityStamp, currentTime, accessTokenExpiresAt, JwtTokenTypes.AccessToken, claims);
            var refreshToken = GenerateToken(subject, securityStamp, currentTime, refreshTokenExpiresAt, JwtTokenTypes.RefreshToken, null);

            var tokenEntity = new JwtToken
            {
                Id = Guid.NewGuid().ToString(),
                Subject = subject,
                IssuedAt = currentTime,
                AccessTokenHash = CryptoHelper.GenerateHash(accessToken),
                AccessTokenExpiresAt = accessTokenExpiresAt,
                RefreshTokenHash = CryptoHelper.GenerateHash(refreshToken),
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

            var fullyExpiredTokens = await _dbContext.Set<JwtToken>()
                .Where(t => t.Subject == subject &&
                            t.AccessTokenExpiresAt < currentTime &&
                            t.RefreshTokenExpiresAt < currentTime)
                .ToListAsync(cancellationToken);

            _dbContext.Set<JwtToken>().RemoveRange(fullyExpiredTokens);

            if (!string.IsNullOrWhiteSpace(tokenString))
            {
                var tokenHash = CryptoHelper.GenerateHash(tokenString);

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

        public async Task<ClaimsPrincipal?> ValidateTokenAsync(string tokenType, string tokenString, CancellationToken cancellationToken = default)
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

            var tokenHash = CryptoHelper.GenerateHash(tokenString);
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

        private string GenerateToken(string subject, string securityStamp, DateTimeOffset issuedAt, DateTimeOffset expiresAt, string tokenType, IEnumerable<Claim>? additionalClaims)
        {
            ArgumentNullException.ThrowIfNull(subject, nameof(subject));
            ArgumentNullException.ThrowIfNull(securityStamp, nameof(securityStamp));
            ArgumentNullException.ThrowIfNull(tokenType, nameof(tokenType));

            if (!JwtTokenTypes.AllTypes.Contains(tokenType, StringComparer.InvariantCulture))
                throw new ArgumentException($"Invalid token type '{tokenType}'.", nameof(tokenType));

            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, subject),
                new(SecurityStampClaimType, securityStamp),
                new(JwtRegisteredClaimNames.Iat, issuedAt.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            if (!string.IsNullOrWhiteSpace(_options.Issuer))
                claims.Add(new Claim(JwtRegisteredClaimNames.Iss, _options.Issuer));

            foreach (var aud in _options.Audience)
                claims.Add(new Claim(JwtRegisteredClaimNames.Aud, aud));

            if (additionalClaims != null)
                claims.AddRange(additionalClaims);

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.Secret));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _options.Issuer,
                claims: claims,
                expires: expiresAt.UtcDateTime,
                notBefore: issuedAt.UtcDateTime,
                signingCredentials: creds);

            token.Header[JwtHeaderParameterNames.Typ] = tokenType;

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private async Task<string> GetOrCreateSecurityStampAsync(string subject, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(subject, nameof(subject));

            var cacheKey = $"{SecurityStampClaimType}:{subject}";

            return await _cacheProvider.GetAsync(cacheKey, async () =>
            {
                var entry = await _dbContext.Set<JwtSecurityStamp>()
                    .FirstOrDefaultAsync(x => x.Subject == subject, cancellationToken);

                if (entry == null)
                {
                    entry = new JwtSecurityStamp
                    {
                        Subject = subject,
                        SecurityStamp = Guid.NewGuid().ToString()
                    };

                    _dbContext.Add(entry);
                    await _dbContext.SaveChangesAsync(cancellationToken);
                }

                return entry.SecurityStamp;
            },
            TimeSpan.FromMinutes(10));
        }

        public async Task<bool> ValidateSecurityStampAsync(string subject, ClaimsPrincipal principal, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(subject, nameof(subject));
            ArgumentNullException.ThrowIfNull(principal, nameof(principal));

            var tokenStamp = principal.Claims
                .FirstOrDefault(x => x.Type == SecurityStampClaimType)?.Value;

            if (string.IsNullOrWhiteSpace(tokenStamp))
                return false;

            var cacheKey = $"{SecurityStampClaimType}:{subject}";

            var currentStamp = await _cacheProvider.GetAsync(cacheKey, async () =>
            {
                return await _dbContext.Set<JwtSecurityStamp>()
                    .Where(x => x.Subject == subject)
                    .Select(x => x.SecurityStamp)
                    .FirstOrDefaultAsync(cancellationToken) ?? string.Empty;
            },
            TimeSpan.FromMinutes(10));

            return tokenStamp == currentStamp;
        }

        public async Task ResetSecurityStampAsync(string subject, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(subject, nameof(subject));

            var entry = await _dbContext.Set<JwtSecurityStamp>()
                .FirstOrDefaultAsync(x => x.Subject == subject, cancellationToken);

            if (entry == null)
                return;

            entry.SecurityStamp = Guid.NewGuid().ToString();
            await _dbContext.SaveChangesAsync(cancellationToken);

            await _cacheProvider.RemoveAsync($"{SecurityStampClaimType}:{subject}");
        }
    }

    public static class JwtTokenTypes
    {
        public const string AccessToken = "at+jwt";
        public const string RefreshToken = "rt+jwt";

        public static readonly string[] AllTypes = [AccessToken, RefreshToken];
    }
}