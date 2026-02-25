namespace MySolution.WebApi.Libraries.CacheProvider
{
    public class MemoryCacheProviderOptions
    {
        public static readonly TimeSpan DefaultCacheTimeSpan = TimeSpan.FromMinutes(60);

        public TimeSpan CacheTimeSpan { get; set; } = DefaultCacheTimeSpan;
    }
}
