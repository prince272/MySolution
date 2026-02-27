using System.Globalization;

namespace MySolution.WebApi.Libraries.Globalizer
{
    public sealed class DefaultGlobalizer : IGlobalizer
    {
        public DefaultGlobalizer(
            TimeProvider timeProvider,
            DeviceProvider deviceProvider,
            HttpUserProvider userProvider,
            CultureInfo culture)
        {
            Time = timeProvider;
            Device = deviceProvider;
            User = userProvider;
            Culture = culture;
        }

        public CultureInfo Culture { get; }
        public RegionInfo Region => new(Culture.Name);
        public TimeProvider Time { get; }
        public DeviceProvider Device { get; }
        public HttpUserProvider User { get; }
    }
}