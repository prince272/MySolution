namespace MySolution.WebApi.Libraries.MessageProvider
{
    public interface IMessageProvider
    {
        MessageChannel Channel { get; }

        Task SendAsync(Message message, CancellationToken cancellationToken = default);
    }
}
