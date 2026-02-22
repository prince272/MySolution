namespace MySolution.WebApi.Libraries.JwtToken
{
    public class JwtToken
    {
        public Guid Id { get; set; }
        public string Subject { get; set; } = null!;
        public DateTimeOffset IssuedAt { get; set; }
        public string AccessTokenHash { get; set; } = null!;
        public DateTimeOffset AccessTokenExpiresAt { get; set; }
        public string RefreshTokenHash { get; set; } = null!;
        public DateTimeOffset RefreshTokenExpiresAt { get; set; }
        public string Scheme { get; set; } = null!;
    }
}
