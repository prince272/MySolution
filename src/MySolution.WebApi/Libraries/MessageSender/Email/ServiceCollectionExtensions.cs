namespace MySolution.WebApi.Libraries.MessageSender.Email
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddEmailProvider(this IServiceCollection services, Action<EmailMessageSenderOptions> configure)
        {
            ArgumentNullException.ThrowIfNull(services, nameof(services));

            services.Configure(configure);

            services.AddScoped<IMessageSender, EmailMessageSender>();

            return services;
        }
    }
}
