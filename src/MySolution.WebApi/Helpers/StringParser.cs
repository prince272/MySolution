using PhoneNumbers;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Mail;
using System.Text.RegularExpressions;
using UAParser;

namespace MySolution.WebApi.Helpers
{
    public static partial class StringParser
    {
        private static readonly PhoneNumberUtil _phoneUtil = PhoneNumberUtil.GetInstance();
        private static readonly Parser _uaParser = Parser.GetDefault();

        public record PhoneInfo(string E164, string CountryCode, string NationalNumber, PhoneNumberType NumberType);
        public record UserAgentInfo(string Browser, string BrowserVersion, string Os, string OsVersion, string Device, DeviceType DeviceType);

        [GeneratedRegex(@"^[-+0-9() ]+$", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
        private static partial Regex PhonePatternRegex();

        public static bool TryParseContactType(string? input, [NotNullWhen(true)] out ContactType? contactType)
        {
            if (string.IsNullOrWhiteSpace(input))
            {
                contactType = null;
                return false;
            }

            var candidate = input.Trim();

            if (candidate.Contains('@'))
            {
                contactType = ContactType.Email;
                return true;
            }

            if (PhonePatternRegex().IsMatch(candidate))
            {
                contactType = ContactType.PhoneNumber;
                return true;
            }

            contactType = null;
            return false;
        }

        public static ContactType ParseContactType(string input)
        {
            ArgumentNullException.ThrowIfNull(input);

            if (!TryParseContactType(input, out var contactType))
                throw new InvalidOperationException("Unable to determine contact type.");

            return contactType.Value;
        }

        public static bool TryParseEmail(string? input, [NotNullWhen(true)] out MailAddress? mailAddress)
        {
            mailAddress = null;
            if (string.IsNullOrWhiteSpace(input)) return false;
            try
            {
                var mail = new MailAddress(input.Trim());
                mailAddress = new MailAddress($"{mail.User.ToLowerInvariant()}@{mail.Host.ToLowerInvariant()}");
                return true;
            }
            catch (FormatException) { return false; }
        }

        public static bool TryParsePhoneNumber(string? input, string? regionCode, [NotNullWhen(true)] out PhoneInfo? info)
        {
            info = null;
            if (string.IsNullOrWhiteSpace(input)) return false;
            try
            {
                var parsed = _phoneUtil.Parse(input.Trim(), regionCode?.ToUpperInvariant());
                if (!_phoneUtil.IsValidNumber(parsed)) return false;
                info = new PhoneInfo(
                    E164: _phoneUtil.Format(parsed, PhoneNumberFormat.E164),
                    CountryCode: $"+{parsed.CountryCode}",
                    NationalNumber: parsed.NationalNumber.ToString(),
                    NumberType: _phoneUtil.GetNumberType(parsed));
                return true;
            }
            catch (NumberParseException) { return false; }
        }

        public static bool TryParseIpAddress(string? input, [NotNullWhen(true)] out IPAddress? ipAddress)
        {
            ipAddress = null;
            if (string.IsNullOrWhiteSpace(input)) return false;
            if (!IPAddress.TryParse(input.Trim(), out ipAddress)) return false;
            return true;
        }

        public static bool TryParseUrl(string? input, [NotNullWhen(true)] out Uri? uri)
        {
            uri = null;
            if (string.IsNullOrWhiteSpace(input)) return false;
            if (!Uri.TryCreate(input.Trim(), UriKind.Absolute, out uri)) return false;
            if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
            {
                uri = null;
                return false;
            }
            return true;
        }

        public static bool TryParseUrlWithAllowedOrigins(string? input, IEnumerable<string> allowedOrigins, [NotNullWhen(true)] out Uri? uri)
        {
            uri = null;
            if (!TryParseUrl(input, out uri)) return false;
            if (!allowedOrigins.Contains(uri.GetLeftPart(UriPartial.Authority), StringComparer.OrdinalIgnoreCase))
            {
                uri = null;
                return false;
            }
            return true;
        }

        public static bool TryParseUserAgent(string? input, [NotNullWhen(true)] out UserAgentInfo? info)
        {
            info = null;
            if (string.IsNullOrWhiteSpace(input)) return false;
            try
            {
                var client = _uaParser.Parse(input.Trim());
                if (client is null) return false;
                var deviceFamily = client.Device.Family ?? string.Empty;
                info = new UserAgentInfo(
                    Browser: client.UA.Family ?? string.Empty,
                    BrowserVersion: $"{client.UA.Major}.{client.UA.Minor}".TrimEnd('.'),
                    Os: client.OS.Family ?? string.Empty,
                    OsVersion: $"{client.OS.Major}.{client.OS.Minor}".TrimEnd('.'),
                    Device: deviceFamily,
                    DeviceType: ResolveDeviceType(client, deviceFamily));
                return true;
            }
            catch (Exception) { return false; }
        }

        private static DeviceType ResolveDeviceType(ClientInfo client, string deviceFamily)
        {
            if (client.Device.IsSpider)
                return DeviceType.Spider;
            if (deviceFamily.Contains("iPad", StringComparison.OrdinalIgnoreCase) ||
                deviceFamily.Contains("Tablet", StringComparison.OrdinalIgnoreCase) ||
                deviceFamily.Contains("Kindle", StringComparison.OrdinalIgnoreCase))
                return DeviceType.Tablet;
            if (deviceFamily.Contains("iPhone", StringComparison.OrdinalIgnoreCase) ||
                deviceFamily.Contains("Android", StringComparison.OrdinalIgnoreCase) ||
                client.OS.Family.Contains("Android", StringComparison.OrdinalIgnoreCase) ||
                client.OS.Family.Contains("iOS", StringComparison.OrdinalIgnoreCase))
                return DeviceType.Mobile;
            if (deviceFamily.Contains("TV", StringComparison.OrdinalIgnoreCase) ||
                deviceFamily.Contains("Chromecast", StringComparison.OrdinalIgnoreCase) ||
                deviceFamily.Contains("FireTV", StringComparison.OrdinalIgnoreCase) ||
                deviceFamily.Contains("AppleTV", StringComparison.OrdinalIgnoreCase) ||
                deviceFamily.Contains("Roku", StringComparison.OrdinalIgnoreCase) ||
                client.OS.Family.Contains("Tizen", StringComparison.OrdinalIgnoreCase) ||
                client.OS.Family.Contains("WebOS", StringComparison.OrdinalIgnoreCase))
                return DeviceType.TV;
            if (deviceFamily.Contains("PlayStation", StringComparison.OrdinalIgnoreCase) ||
                deviceFamily.Contains("Xbox", StringComparison.OrdinalIgnoreCase) ||
                deviceFamily.Contains("Nintendo", StringComparison.OrdinalIgnoreCase))
                return DeviceType.Console;
            if (deviceFamily.Contains("Watch", StringComparison.OrdinalIgnoreCase) ||
                deviceFamily.Contains("Wearable", StringComparison.OrdinalIgnoreCase) ||
                client.OS.Family.Contains("watchOS", StringComparison.OrdinalIgnoreCase) ||
                client.OS.Family.Contains("Wear OS", StringComparison.OrdinalIgnoreCase))
                return DeviceType.Wearable;
            if (client.OS.Family.Contains("Windows", StringComparison.OrdinalIgnoreCase) ||
                client.OS.Family.Contains("Mac OS X", StringComparison.OrdinalIgnoreCase) ||
                client.OS.Family.Contains("Linux", StringComparison.OrdinalIgnoreCase) ||
                client.OS.Family.Contains("Chrome OS", StringComparison.OrdinalIgnoreCase) ||
                client.OS.Family.Contains("Ubuntu", StringComparison.OrdinalIgnoreCase) ||
                client.OS.Family.Contains("Fedora", StringComparison.OrdinalIgnoreCase))
                return DeviceType.Desktop;
            return DeviceType.Unknown;
        }

        private static bool IsPrivateIp(IPAddress ip)
        {
            var bytes = ip.GetAddressBytes();
            return ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && (
                bytes[0] == 10 ||
                (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                (bytes[0] == 192 && bytes[1] == 168));
        }

        public static bool IsPrivateIpAddress(this IPAddress ip) => IsPrivateIp(ip);
        public static bool IsLoopbackIpAddress(this IPAddress ip) => IPAddress.IsLoopback(ip);
        public static IpAddressFamily GetIpAddressFamily(this IPAddress ip) =>
            ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                ? IpAddressFamily.IPv6
                : IpAddressFamily.IPv4;
    }

    public enum ContactType { Email, PhoneNumber }
    public enum IpAddressFamily { IPv4, IPv6 }
    public enum DeviceType { Desktop, Mobile, Tablet, TV, Console, Wearable, Spider, Unknown }
}