using Microsoft.Extensions.Options;

namespace MySolution.WebApi.Libraries.MessageSender.Sms
{
    public class SmsMessageSender : IMessageSender
    {
        private readonly SmsMessageSenderOptions _options;

        public MessageChannel Channel => MessageChannel.Sms;

        public SmsMessageSender(IOptions<SmsMessageSenderOptions> options)
        {
            _options = options.Value;
        }

        public Task SendAsync(Message message, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(message, nameof(message));

            Console.WriteLine($"Sending SMS via API Key: {_options.ApiKey}");
            Console.WriteLine($"To: {message.To}");
            Console.WriteLine($"Body: {message.Body}");

            return Task.CompletedTask;
        }
    }
}