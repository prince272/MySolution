using System.Globalization;

namespace MySolution.WebApi.Libraries.Globalizer
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddGlobalizer(this IServiceCollection services)
        {
            ArgumentNullException.ThrowIfNull(services, nameof(services));

            services.AddScoped<IGlobalizer>(provider =>
            {
                return new DefaultGlobalizer(
                    timeProvider: TimeProvider.System,
                    deviceProvider: DeviceProvider.System,
                    culture: CultureInfo.CurrentCulture);
            });
            return services;
        }
    }
}
