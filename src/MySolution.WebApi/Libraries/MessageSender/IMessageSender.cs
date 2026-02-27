namespace MySolution.WebApi.Libraries.MessageSender
{
    public interface IMessageSender
    {
        MessageChannel Channel { get; }

        Task SendAsync(Message message, CancellationToken cancellationToken = default);
    }
}
