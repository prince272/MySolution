using Microsoft.Extensions.Caching.Memory;

namespace MySolution.WebApi.Libraries.CacheProvider
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddMemoyCacheProvider(
            this IServiceCollection services,
            Action<MemoryCacheProviderOptions>? configure = null)
        {
            ArgumentNullException.ThrowIfNull(services, nameof(services));

            services.AddMemoryCache();
            services.AddOptions<MemoryCacheProviderOptions>();

            if (configure is not null)
                services.Configure(configure);

            services.AddSingleton<ICacheProvider, MemoryCacheProvider>();

            return services;
        }
    }
}
