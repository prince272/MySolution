using System.Globalization;

namespace MySolution.WebApi.Libraries.Globalizer
{
    public static class GlobalizerServiceCollectionExtensions
    {
        public static IServiceCollection AddGlobalizer(this IServiceCollection services)
        {
            services.AddScoped<IGlobalizer>(provider =>
            {
                return new DefaultGlobalizer(
                    timeProvider: TimeProvider.System,
                    culture: CultureInfo.CurrentCulture);
            });
            return services;
        }
    }
}
