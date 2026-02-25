using System.Security.Claims;

namespace MySolution.WebApi.Libraries.JwtTokenProvider
{
    public interface IJwtTokenProvider
    {
        Task<JwtRawToken> CreateTokenAsync(string subject, IEnumerable<Claim>? claims = null, CancellationToken cancellationToken = default);
        Task RevokeAllTokensAsync(string subject, CancellationToken cancellationToken = default);
        Task RevokeExpiredTokensAsync(string subject, CancellationToken cancellationToken = default);
        Task RevokeTokenAsync(string subject, string tokenString, CancellationToken cancellationToken = default);
        Task<ClaimsPrincipal?> ValidateTokenAsync(string tokenType, string tokenString, CancellationToken cancellationToken = default);
        Task<bool> ValidateSecurityStampAsync(string subject, ClaimsPrincipal principal, CancellationToken cancellationToken = default);
        Task ResetSecurityStampAsync(string subject, CancellationToken cancellationToken = default);
    }
}
