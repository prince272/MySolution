using Microsoft.Extensions.Options;

namespace MySolution.WebApi.Libraries.MessageProvider.Sms
{
    public class SmsMessageProvider : IMessageProvider
    {
        private readonly SmsOptions _options;

        public MessageChannel Channel => MessageChannel.Sms;

        public SmsMessageProvider(IOptions<SmsOptions> options)
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