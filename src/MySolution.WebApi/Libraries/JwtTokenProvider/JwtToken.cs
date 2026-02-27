namespace MySolution.WebApi.Libraries.JwtTokenProvider
{
    public class JwtToken
    {
        public string Id { get; set; } = null!;
        public string Subject { get; set; } = null!;
        public DateTimeOffset IssuedAt { get; set; }
        public string AccessTokenHash { get; set; } = null!;
        public DateTimeOffset AccessTokenExpiresAt { get; set; }
        public string RefreshTokenHash { get; set; } = null!;
        public DateTimeOffset RefreshTokenExpiresAt { get; set; }
    }
}
