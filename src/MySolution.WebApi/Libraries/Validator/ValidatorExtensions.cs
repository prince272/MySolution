using FluentValidation;
using Humanizer;
using MySolution.WebApi.Helpers;

namespace MySolution.WebApi.Libraries.Validator
{
    public static class ValidationExtensions
    {
        public static IRuleBuilderOptions<T, string> Email<T>(this IRuleBuilder<T, string> ruleBuilder)
        {
            return ruleBuilder.Must((value) => StringParser.TryParseEmail(value, out var _)).WithMessage("'{PropertyName}' is not valid.");
        }

        public static IRuleBuilderOptions<T, string> PhoneNumber<T>(this IRuleBuilder<T, string> ruleBuilder, string? regionCode = null)
        {
            return ruleBuilder.Must((value) => StringParser.TryParsePhoneNumber(value, regionCode, out var _)).WithMessage("'{PropertyName}' is not valid.");
        }

        // How can I create strong passwords with FluentValidation?
        // Source: https://stackoverflow.com/questions/63864594/how-can-i-create-strong-passwords-with-fluentvalidation
        public static IRuleBuilderOptions<T, string> Password<T>(this IRuleBuilderOptions<T, string> ruleBuilder, int minimumLength = 6)
        {
            var options = ruleBuilder
                .MinimumLength(minimumLength)
                .Matches("[A-Z]").WithMessage("'{PropertyName}' must contain at least 1 upper case.")
                .Matches("[a-z]").WithMessage("'{PropertyName}' must contain at least 1 lower case.")
                .Matches("[0-9]").WithMessage("'{PropertyName}' must contain at least 1 digit.")
                .Matches("[^a-zA-Z0-9]").WithMessage("'{PropertyName}' must contain at least 1 special character.");

            return options;
        }

        public static IRuleBuilderOptionsConditions<T, string> Username<T>(this IRuleBuilder<T, string> ruleBuilder, string currentRegionCode)
        {
            return ruleBuilder.Custom((username, context) =>
            {
                if (string.IsNullOrWhiteSpace(username)) return;

                var displayName = context.DisplayName;
                var usernameIndex = displayName.IndexOf("Username", StringComparison.OrdinalIgnoreCase);
                var prefix = usernameIndex > 0 ? displayName[..usernameIndex].Trim() : string.Empty;

                if (!StringParser.TryParseContactType(username, out var contactType))
                {
                    context.AddFailure(context.PropertyPath, $"'{displayName}' is not valid.");
                    return;
                }

                var (isValid, baseLabel) = contactType switch
                {
                    ContactType.Email => (StringParser.TryParseEmail(username, out _), "Email"),
                    ContactType.PhoneNumber => (StringParser.TryParsePhoneNumber(username, currentRegionCode, out _), "Phone number"),
                    _ => (false, displayName)
                };

                var label = string.IsNullOrEmpty(prefix) ? baseLabel : $"{prefix} {baseLabel.Humanize(LetterCasing.LowerCase)}";

                if (!isValid) context.AddFailure(context.PropertyPath, $"'{label}' is not valid.");
            });
        }
    }
}