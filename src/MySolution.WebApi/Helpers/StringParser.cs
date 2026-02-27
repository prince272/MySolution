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

        public record EmailInfo(string Address, string LocalPart, string Domain);
        public record PhoneInfo(string E164, string CountryCode, string NationalNumber, PhoneNumberType NumberType);
        public record IpAddressInfo(string Address, IpAddressFamily Family, bool IsLoopback, bool IsPrivate);
        public record UserAgentInfo(string Browser, string BrowserVersion, string Os, string OsVersion, string Device, DeviceType DeviceType);

        [GeneratedRegex(@"^[-+0-9() ]+$", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
        private static partial Regex PhonePatternRegex();

        public static ContactType? DetectContactType(string? input)
        {
            if (string.IsNullOrWhiteSpace(input)) return null;
            var candidate = input.Trim();
            if (candidate.Contains('@')) return ContactType.Email;
            if (PhonePatternRegex().IsMatch(candidate)) return ContactType.PhoneNumber;
            return null;
        }

        public static bool TryParseEmail(string? input, [NotNullWhen(true)] out EmailInfo? info)
        {
            info = null;
            if (string.IsNullOrWhiteSpace(input)) return false;
            try
            {
                var mail = new MailAddress(input.Trim());
                var localPart = mail.User.ToLowerInvariant();
                var domain = mail.Host.ToLowerInvariant();
                info = new EmailInfo(
                    Address: $"{localPart}@{domain}",
                    LocalPart: localPart,
                    Domain: domain);
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

        public static bool TryParseIpAddress(string? input, [NotNullWhen(true)] out IpAddressInfo? info)
        {
            info = null;
            if (string.IsNullOrWhiteSpace(input)) return false;
            if (!IPAddress.TryParse(input.Trim(), out var ip)) return false;
            info = new IpAddressInfo(
                Address: ip.ToString(),
                Family: ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                    ? IpAddressFamily.IPv6
                    : IpAddressFamily.IPv4,
                IsLoopback: IPAddress.IsLoopback(ip),
                IsPrivate: IsPrivateIp(ip));
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
    }

    public enum ContactType
    {
        Email,
        PhoneNumber
    }

    public enum IpAddressFamily
    {
        IPv4,
        IPv6
    }

    public enum DeviceType
    {
        Desktop,
        Mobile,
        Tablet,
        TV,
        Console,
        Wearable,
        Spider,
        Unknown
    }
}