namespace MySolution.WebApi.Libraries.MessageSender.Sms
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddSmsSender(this IServiceCollection services, Action<SmsMessageSenderOptions> configure)
        {
            ArgumentNullException.ThrowIfNull(services, nameof(services));

            services.Configure(configure);

            services.AddScoped<IMessageSender, SmsMessageSender>();

            return services;
        }
    }
}
