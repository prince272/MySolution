using System.Globalization;

namespace MySolution.WebApi.Libraries.Globalizer
{
    public interface IGlobalizer
    {
        CultureInfo Culture { get; }
        RegionInfo Region { get; }
        TimeProvider Time { get; }
        DeviceProvider Device { get; }
        HttpUserProvider User { get; }
    }
}