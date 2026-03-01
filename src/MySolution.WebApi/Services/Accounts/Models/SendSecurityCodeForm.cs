using FluentValidation;
using Humanizer;
using MySolution.WebApi.Helpers;
using MySolution.WebApi.Libraries.Globalizer;
using MySolution.WebApi.Libraries.Validator;
using MySolution.WebApi.Services.Accounts.Entities;
using MySolution.WebApi.Services.Accounts.Repositories;

namespace MySolution.WebApi.Services.Accounts.Models
{
    public class SendSecurityCodeForm
    {
        public string CurrentUsername { get; set; } = null!;
        public string? NewUsername { get; set; } = null!;
        public SecurityReason Reason { get; set; }
    }

    public enum SecurityReason
    {
        VerifyAccount,
        ChangeAccount,
        ResetPassword,
    }

    public class SendSecurityCodeFormValidator<TForm> : AbstractValidator<TForm> where TForm : SendSecurityCodeForm
    {
        public SendSecurityCodeFormValidator(IGlobalizer globalizer, IUserRepository userRepository)
        {
            var currentRegionCode = globalizer.Region.TwoLetterISORegionName.ToUpperInvariant();

            RuleFor(x => x.CurrentUsername)
                .NotEmpty()
                .MaximumLength(128)
                .Username(currentRegionCode)
                .CustomAsync(async (currentUsername, context, cancellationToken) =>
                {
                    var reason = context.InstanceToValidate.Reason;

                    if (reason == SecurityReason.ChangeAccount)
                    {
                        var authenticatedUser =
                            await userRepository.GetByEmailOrPhoneAsync(currentUsername, cancellationToken);

                        if (authenticatedUser == null || authenticatedUser.Id != globalizer.User.Id)
                        {
                            context.AddFailure(context.PropertyPath, $"'Current {StringParser.ParseContactType(currentUsername).Humanize(LetterCasing.LowerCase)}' is invalid.");
                        }


                        context.RootContextData[nameof(User)] = authenticatedUser;
                    }
                    else
                    {
                        var user = await userRepository.GetByEmailOrPhoneAsync(currentUsername, cancellationToken);

                        if (user == null)
                        {
                            context.AddFailure(context.PropertyPath, $"'Current {StringParser.ParseContactType(currentUsername).Humanize(LetterCasing.LowerCase)}' is invalid.");
                        }

                        context.RootContextData[nameof(User)] = user;
                    }
                });

            RuleFor(x => x.NewUsername)
                .NotEmpty()
                .MaximumLength(128)
                .Username(currentRegionCode)
                .NotEqual(x => x.CurrentUsername, StringComparer.OrdinalIgnoreCase)
                .CustomAsync(async (newUsername, context, cancellationToken) =>
                {
                    var exists = await userRepository.ExistsByEmailOrPhoneAsync(newUsername!, cancellationToken);

                    if (exists)
                    {
                        context.AddFailure(context.PropertyPath, $"'New {StringParser.ParseContactType(newUsername!).Humanize(LetterCasing.LowerCase)}' already exists.");
                    }
                })
                .When(x => x.Reason == SecurityReason.ChangeAccount, ApplyConditionTo.AllValidators);
        }
    }

    public class SendSecurityCodeFormValidator : SendSecurityCodeFormValidator<SendSecurityCodeForm>
    {
        public SendSecurityCodeFormValidator(IGlobalizer globalizer, IUserRepository userRepository) : base(globalizer, userRepository)
        {
        }
    }
}