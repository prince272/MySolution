using DeviceId;
using System.Globalization;

namespace MySolution.WebApi.Libraries.Globalizer
{
    public sealed class DefaultGlobalizer : IGlobalizer
    {
        public DefaultGlobalizer(TimeProvider timeProvider, DeviceProvider deviceProvider, CultureInfo culture)
        {
            Time = timeProvider;
            Device = deviceProvider;
            Culture = culture;
        }

        public CultureInfo Culture { get; }
        public RegionInfo Region => new(Culture.Name);
        public TimeProvider Time { get; }
        public DeviceProvider Device { get; }
    }

    public abstract class DeviceProvider
    {
        public static DeviceProvider System { get; } = new SystemDeviceProvider();

        private readonly Lazy<string> _deviceId;

        protected DeviceProvider()
        {
            _deviceId = new Lazy<string>(BuildDeviceId);
        }

        public string Id => _deviceId.Value;

        public virtual string MachineName => Environment.MachineName;

        public virtual string OsVersion => Environment.OSVersion.ToString();

        public virtual string UserName => Environment.UserName;

        protected abstract string BuildDeviceId();

        private sealed class SystemDeviceProvider : DeviceProvider
        {
            protected override string BuildDeviceId() =>
                new DeviceIdBuilder()
                    .AddMachineName()
                    .AddOsVersion()
                    .AddUserName()
                    .AddMacAddress()
                    .AddFileToken("device-token.txt")
                    .ToString();
        }
    }
}