namespace MySolution.WebApi.Libraries.MessageProvider
{
    public static class MessageProviderExtensions
    {
        public static async Task SendAsync(
            this IEnumerable<IMessageProvider> providers,
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
