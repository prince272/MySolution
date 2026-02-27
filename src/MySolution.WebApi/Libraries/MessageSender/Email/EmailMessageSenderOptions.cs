namespace MySolution.WebApi.Libraries.MessageSender.Email
{
    public class EmailMessageSenderOptions
    {
        public string SmtpHost { get; set; } = default!;
        public int Port { get; set; }
        public string Username { get; set; } = default!;
        public string Password { get; set; } = default!;
        public string DisplayName { get; set; } = default!;
    }
}
