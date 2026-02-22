namespace MySolution.WebApi.Libraries.JwtToken
{
    public class JwtRawToken
    {
        public string Scheme { get; set; } = null!;
        public string AccessToken { get; set; } = null!;
        public DateTimeOffset AccessTokenExpiresAt { get; set; }
        public string RefreshToken { get; set; } = null!;
        public DateTimeOffset RefreshTokenExpiresAt { get; set; }
    }
}
