namespace MySolution.WebApi.Libraries.JwtTokenProvider
{
    public class JwtTokenOptions
    {
        public string Secret { get; set; } = null!;
        public string Issuer { get; set; } = null!;
        public string[] Audience { get; set; } = null!;
        public TimeSpan AccessTokenExpiresIn { get; set; } = TimeSpan.FromMinutes(15);
        public TimeSpan RefreshTokenExpiresIn { get; set; } = TimeSpan.FromDays(30);
    }
}
