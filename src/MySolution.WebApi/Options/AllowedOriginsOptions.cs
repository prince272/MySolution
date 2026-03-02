namespace MySolution.WebApi.Options
{
    public class AllowedOriginsOptions
    {
        public string AllowedOrigins { get; set; } = null!;

        public bool AllowAnyOrigin => AllowedOrigins?.Trim() == "*";

        public string[] GetOrigins() => AllowedOrigins?.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries) ?? [];
    }
}
