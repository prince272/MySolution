namespace MySolution.WebApi.Libraries.CacheProvider
{
    public interface ICacheProvider
    {
        Task<T> GetAsync<T>(string key, Func<Task<T>> acquire);
        Task<T> GetAsync<T>(string key, Func<Task<T>> acquire, TimeSpan cacheTime);

        Task<T> SetAsync<T>(string key, Func<Task<T>> acquire);
        Task<T> SetAsync<T>(string key, Func<Task<T>> acquire, TimeSpan cacheTime);

        Task RemoveAsync(string key);
        Task RemoveByPrefix(string prefix);
        Task Clear();
    }
}
