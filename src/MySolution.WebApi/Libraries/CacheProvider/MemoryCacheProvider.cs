using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using System.Collections.Concurrent;

namespace MySolution.WebApi.Libraries.CacheProvider
{
    public class MemoryCacheProvider : ICacheProvider
    {
        private readonly IMemoryCache _cache;
        private readonly MemoryCacheProviderOptions _options;

        private static CancellationTokenSource _resetCacheToken = new();
        protected readonly ConcurrentDictionary<string, SemaphoreSlim> CacheEntries = new();

        public MemoryCacheProvider(IMemoryCache cache, IOptions<MemoryCacheProviderOptions> options)
        {
            _options = options.Value;
            _cache = cache;
        }

        public Task<T> GetAsync<T>(string key, Func<Task<T>> acquire)
            => GetAsync(key, acquire, _options.CacheTimeSpan);

        public async Task<T> GetAsync<T>(string key, Func<Task<T>> acquire, TimeSpan cacheTime)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(key, nameof(key));
            ArgumentNullException.ThrowIfNull(acquire, nameof(acquire));
            ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(cacheTime, TimeSpan.Zero, nameof(cacheTime));

            if (_cache.TryGetValue(key, out T? cacheEntry)) return cacheEntry ?? default!;

            var semaphore = CacheEntries.GetOrAdd(key, _ => new SemaphoreSlim(1, 1));
            await semaphore.WaitAsync();
            try
            {
                if (!_cache.TryGetValue(key, out cacheEntry))
                {
                    cacheEntry = await acquire();
                    _cache.Set(key, cacheEntry, GetMemoryCacheEntryOptions(cacheTime));
                }
            }
            finally
            {
                semaphore.Release();
            }

            return cacheEntry ?? default!;
        }

        public Task<T> SetAsync<T>(string key, Func<Task<T>> acquire)
            => SetAsync(key, acquire, _options.CacheTimeSpan);

        public async Task<T> SetAsync<T>(string key, Func<Task<T>> acquire, TimeSpan cacheTime)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(key, nameof(key));
            ArgumentNullException.ThrowIfNull(acquire, nameof(acquire));
            ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(cacheTime, TimeSpan.Zero, nameof(cacheTime));

            var semaphore = CacheEntries.GetOrAdd(key, _ => new SemaphoreSlim(1, 1));
            await semaphore.WaitAsync();
            try
            {
                var cacheEntry = await acquire();
                _cache.Set(key, cacheEntry, GetMemoryCacheEntryOptions(cacheTime));
                return cacheEntry;
            }
            finally
            {
                semaphore.Release();
            }
        }

        public Task RemoveAsync(string key)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(key, nameof(key));

            _cache.Remove(key);
            return Task.CompletedTask;
        }

        public Task RemoveByPrefix(string prefix)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(prefix, nameof(prefix));

            var entriesToRemove = CacheEntries
                .Where(x => x.Key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));

            foreach (var entry in entriesToRemove)
                _cache.Remove(entry.Key);

            return Task.CompletedTask;
        }

        public Task Clear()
        {
            foreach (var key in CacheEntries.Keys.ToList())
                _cache.Remove(key);

            _resetCacheToken.Cancel();
            _resetCacheToken.Dispose();
            _resetCacheToken = new CancellationTokenSource();

            return Task.CompletedTask;
        }

        private MemoryCacheEntryOptions GetMemoryCacheEntryOptions(TimeSpan cacheTime)
        {
            return new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = cacheTime
            }
                .AddExpirationToken(new CancellationChangeToken(_resetCacheToken.Token))
                .RegisterPostEvictionCallback(PostEvictionCallback);
        }

        private void PostEvictionCallback(object key, object? value, EvictionReason reason, object? state)
        {
            if (reason != EvictionReason.Replaced)
                CacheEntries.TryRemove(key.ToString()!, out _);
        }
    }
}