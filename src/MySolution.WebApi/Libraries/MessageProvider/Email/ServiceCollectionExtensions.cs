namespace MySolution.WebApi.Libraries.MessageProvider.Email
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddEmailProvider(this IServiceCollection services, Action<EmailOptions> configure)
        {
            ArgumentNullException.ThrowIfNull(services, nameof(services));

            services.Configure(configure);

            services.AddScoped<IMessageProvider, EmailMessageProvider>();

            return services;
        }
    }
}
