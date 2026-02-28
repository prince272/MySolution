using System.Security.Claims;

namespace MySolution.WebApi.Libraries.JwtTokenProvider
{
    public interface IJwtTokenProvider
    {
        Task<JwtRawToken> CreateTokenAsync(string subject, IEnumerable<Claim>? claims = null, CancellationToken cancellationToken = default);
        Task RevokeAllTokensAsync(string subject, CancellationToken cancellationToken = default);
        Task RevokeRefreshTokenAsync(string subject, string refreshToken, CancellationToken cancellationToken = default);
        Task<ClaimsPrincipal?> ValidateRefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default);
        Task<bool> ValidateSecurityStampAsync(string subject, ClaimsPrincipal principal, CancellationToken cancellationToken = default);
        Task ResetSecurityStampAsync(string subject, CancellationToken cancellationToken = default);
    }
}
