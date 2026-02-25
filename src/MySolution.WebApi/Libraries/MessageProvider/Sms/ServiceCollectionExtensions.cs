namespace MySolution.WebApi.Libraries.MessageProvider.Sms
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddSmsProvider(this IServiceCollection services, Action<SmsOptions> configure)
        {
            ArgumentNullException.ThrowIfNull(services, nameof(services));

            services.Configure(configure);

            services.AddScoped<IMessageProvider, SmsMessageProvider>();

            return services;
        }
    }
}
