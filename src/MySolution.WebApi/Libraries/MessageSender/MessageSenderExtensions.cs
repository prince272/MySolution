namespace MySolution.WebApi.Libraries.MessageSender
{
    public static class MessageSenderExtensions
    {
        public static async Task SendAsync(
            this IEnumerable<IMessageSender> providers,
            MessageChannel channel,
            Message message,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(providers, nameof(providers));
            ArgumentNullException.ThrowIfNull(message, nameof(message));

            var provider = providers.FirstOrDefault(p => p.Channel == channel) ?? throw new InvalidOperationException($"Channel '{channel}' not supported.");
            await provider.SendAsync(message, cancellationToken);
        }
    }
}
