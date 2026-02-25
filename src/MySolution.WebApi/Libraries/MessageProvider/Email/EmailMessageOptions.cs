namespace MySolution.WebApi.Libraries.MessageProvider.Email
{
    public class EmailOptions
    {
        public string SmtpHost { get; set; } = default!;
        public int Port { get; set; }
        public string Username { get; set; } = default!;
        public string Password { get; set; } = default!;
        public string FromName { get; set; } = default!;
    }
}
