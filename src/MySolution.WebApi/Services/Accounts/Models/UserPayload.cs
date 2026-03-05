namespace MySolution.WebApi.Services.Accounts.Models
{
    public class UserPayload
    {
        public string ProviderName { get; set; } = null!;

        public string FirstName { get; set; } = null!;

        public string? LastName { get; set; }

        public string Username { get; set; } = null!;
    }
}
