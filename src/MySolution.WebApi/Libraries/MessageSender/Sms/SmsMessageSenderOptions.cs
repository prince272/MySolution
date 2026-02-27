namespace MySolution.WebApi.Libraries.MessageSender.Sms
{
    public class SmsMessageSenderOptions
    {
        public string ApiKey { get; set; } = default!;
        public string SenderId { get; set; } = default!;
    }
}
