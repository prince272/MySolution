using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;
using MimeKit.Text;

namespace MySolution.WebApi.Libraries.MessageProvider.Email
{
    public class EmailMessageProvider : IMessageProvider
    {
        private readonly EmailOptions _options;

        public EmailMessageProvider(IOptions<EmailOptions> options)
        {
            _options = options.Value;
        }

        public MessageChannel Channel => MessageChannel.Email;

        public async Task SendAsync(Message message, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(message, nameof(message));

            var mimeMessage = new MimeMessage();

            mimeMessage.From.Add(MailboxAddress.Parse(_options.Username));
            mimeMessage.To.Add(MailboxAddress.Parse(message.To));
            mimeMessage.Subject = message.Subject;

            mimeMessage.Body = new TextPart(TextFormat.Html)
            {
                Text = message.Body
            };

            using var client = new SmtpClient();

            await client.ConnectAsync(_options.SmtpHost, _options.Port, SecureSocketOptions.StartTls, cancellationToken);
            await client.AuthenticateAsync(_options.Username, _options.Password, cancellationToken);
            await client.SendAsync(mimeMessage, cancellationToken);
            await client.DisconnectAsync(quit: true, cancellationToken);
        }
    }
}