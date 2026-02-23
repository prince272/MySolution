using System.Globalization;

namespace MySolution.WebApi.Libraries.Globalizer
{
    public class DefaultGlobalizer : IGlobalizer
    {
        private readonly TimeProvider _time;
        private readonly CultureInfo _culture;

        public DefaultGlobalizer(TimeProvider timeProvider, CultureInfo culture)
        {
            _time = timeProvider;
            _culture = culture;
        }

        public CultureInfo Culture => _culture;
        public RegionInfo Region => new(_culture.Name);
        public TimeProvider Time => _time;
    }

    public interface IGlobalizer
    {
        CultureInfo Culture { get; }
        RegionInfo Region { get; }
        TimeProvider Time { get; }
    }
}