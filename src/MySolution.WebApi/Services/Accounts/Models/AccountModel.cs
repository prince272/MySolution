namespace MySolution.WebApi.Services.Accounts.Models
{
    public class AccountModel : ProfileModel
    {
        public string AccessToken { get; set; } = null!;
        public DateTimeOffset AccessTokenExpiresAt { get; set; }
        public string RefreshToken { get; set; } = null!;
        public DateTimeOffset RefreshTokenExpiresAt { get; set; }
    }
}
