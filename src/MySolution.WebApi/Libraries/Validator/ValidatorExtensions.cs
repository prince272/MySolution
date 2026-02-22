using FluentValidation;
using MySolution.WebApi.Helpers;

namespace MySolution.WebApi.Libraries.Validator
{
    public static class ValidationExtensions
    {
        public static IRuleBuilderOptions<T, string> Email<T>(this IRuleBuilder<T, string> ruleBuilder)
        {
            return ruleBuilder.Must((value) => ContactHelper.TryParseEmail(value, out var _)).WithMessage("'{PropertyName}' is not valid.");
        }

        public static IRuleBuilderOptions<T, string> PhoneNumber<T>(this IRuleBuilder<T, string> ruleBuilder, string? regionCode = null)
        {
            return ruleBuilder.Must((value) => ContactHelper.TryParsePhoneNumber(value, regionCode, out var _)).WithMessage("'{PropertyName}' is not valid.");
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
    }
}