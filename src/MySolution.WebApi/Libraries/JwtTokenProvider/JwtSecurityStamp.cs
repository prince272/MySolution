namespace MySolution.WebApi.Libraries.JwtTokenProvider
{
    public class JwtSecurityStamp
    {
        public string Subject { get; set; } = default!;
        public string SecurityStamp { get; set; } = default!;
    }
}
