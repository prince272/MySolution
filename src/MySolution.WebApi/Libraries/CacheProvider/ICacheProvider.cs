namespace MySolution.WebApi.Libraries.CacheProvider
{
    public interface ICacheProvider
    {
        Task<T> GetAsync<T>(string key, Func<Task<T>> acquire, CancellationToken cancellationToken = default);
        Task<T> GetAsync<T>(string key, Func<Task<T>> acquire, TimeSpan cacheTime, CancellationToken cancellationToken = default);

        Task<T> SetAsync<T>(string key, Func<Task<T>> acquire, CancellationToken cancellationToken = default);
        Task<T> SetAsync<T>(string key, Func<Task<T>> acquire, TimeSpan cacheTime, CancellationToken cancellationToken = default);

        Task<long> IncrementAsync(string key, long value = 1, TimeSpan? cacheTime = null, CancellationToken cancellationToken = default);
        Task<long> DecrementAsync(string key, long value = 1, TimeSpan? cacheTime = null, CancellationToken cancellationToken = default);

        Task RemoveAsync(string key, CancellationToken cancellationToken = default);
        Task RemoveByPrefix(string prefix, CancellationToken cancellationToken = default);
        Task Clear(CancellationToken cancellationToken = default);
    }
}
