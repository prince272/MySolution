using System.Diagnostics.CodeAnalysis;
using System.Net.Mail;
using System.Text.RegularExpressions;
using PhoneNumbers;
namespace MySolution.WebApi.Helpers
{
    public static partial class ContactHelper
    {
        private static readonly PhoneNumberUtil _phoneUtil = PhoneNumberUtil.GetInstance();
        public record EmailInfo(string Address, string LocalPart, string Domain);
        public record PhoneInfo(string E164, string CountryCode, string NationalNumber, PhoneNumberType NumberType);

        [GeneratedRegex(@"^[-+0-9() ]+$", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
        private static partial Regex PhonePatternRegex();

        public static ContactType? DetectContactType(string? input)
        {
            if (string.IsNullOrWhiteSpace(input)) return null;
            var candidate = input.Trim();
            if (candidate.Contains('@'))
                return ContactType.Email;
            if (PhonePatternRegex().IsMatch(candidate))
                return ContactType.PhoneNumber;
            return null;
        }

        public static bool TryParseEmail(string? input, [NotNullWhen(true)] out EmailInfo? info)
        {
            info = null;
            if (string.IsNullOrWhiteSpace(input))
                return false;
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
            catch (FormatException)
            {
                return false;
            }
        }

        public static bool TryParsePhoneNumber(string? input, string? regionCode, [NotNullWhen(true)] out PhoneInfo? info)
        {
            info = null;
            if (string.IsNullOrWhiteSpace(input))
                return false;
            try
            {
                var parsed = _phoneUtil.Parse(input.Trim(), regionCode?.ToUpperInvariant());
                if (!_phoneUtil.IsValidNumber(parsed))
                    return false;
                info = new PhoneInfo(
                    E164: _phoneUtil.Format(parsed, PhoneNumberFormat.E164),
                    CountryCode: $"+{parsed.CountryCode}",
                    NationalNumber: parsed.NationalNumber.ToString(),
                    NumberType: _phoneUtil.GetNumberType(parsed));
                return true;
            }
            catch (NumberParseException)
            {
                return false;
            }
        }
    }

    public enum ContactType { Email, PhoneNumber }
}