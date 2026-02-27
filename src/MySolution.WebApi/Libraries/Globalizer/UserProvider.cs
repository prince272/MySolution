using MySolution.WebApi.Services.Accounts.Entities;
using Org.BouncyCastle.Asn1.Ocsp;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using System.Threading.Channels;

namespace MySolution.WebApi.Libraries.Globalizer
{
    public abstract class UserProvider
    {
        public abstract string? Id { get; }
        public abstract string? UserAgent { get; }
        public abstract string? IpAddress { get; }

        [MemberNotNullWhen(true, nameof(Id))]
        public abstract bool IsAuthenticated { get; }
    }

    public sealed class HttpUserProvider : UserProvider
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        public HttpUserProvider(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        private HttpContext? HttpContext => _httpContextAccessor.HttpContext;

        public override string? Id => HttpContext?.User?.FindFirstValue("sub");
        public override string? UserAgent => HttpContext?.Request?.Headers.UserAgent.ToString() is { Length: > 0 } ua ? ua : null;
        public override string? IpAddress => HttpContext?.Connection?.RemoteIpAddress?.ToString(); 

        [MemberNotNullWhen(true, nameof(Id))]
        public override bool IsAuthenticated => HttpContext?.User?.Identity?.IsAuthenticated ?? false;
    }
}