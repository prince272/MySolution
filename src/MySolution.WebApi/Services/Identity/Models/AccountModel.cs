using MySolution.WebApi.Libraries.JwtToken;
using MySolution.WebApi.Services.Identity.Entities;

namespace MySolution.WebApi.Services.Identity.Models
{
    public class AccountModel : ProfileModel
    {
        public string TokenScheme { get; set; } = null!;
        public string AccessToken { get; set; } = null!;
        public DateTimeOffset AccessTokenExpiresAt { get; set; }
        public string RefreshToken { get; set; } = null!;
        public DateTimeOffset RefreshTokenExpiresAt { get; set; }
    }
}
