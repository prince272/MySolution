using FluentValidation;
using MySolution.WebApi.Helpers;
using MySolution.WebApi.Libraries.Globalizer;
using MySolution.WebApi.Libraries.Validator;
using MySolution.WebApi.Services.Accounts.Entities;
using MySolution.WebApi.Services.Accounts.Repositories;

namespace MySolution.WebApi.Services.Accounts.Models
{
    public class ChangePasswordForm
    {
        public string CurrentPassword { get; set; } = null!;
        public string NewPassword { get; set; } = null!;
        public string ConfirmPassword { get; set; } = null!;
    }

    public class ChangePasswordFormValidator : AbstractValidator<ChangePasswordForm>
    {
        public ChangePasswordFormValidator(IGlobalizer globalizer, IUserRepository userRepository)
        {
            RuleFor(_ => _.CurrentPassword)
                .NotEmpty()
                .MaximumLength(128)
                .CustomAsync(async (currentPassword, context, cancellationToken) =>
                {
                    var user = !string.IsNullOrWhiteSpace(globalizer.User.Id) ? await userRepository.GetByIdAsync(globalizer.User.Id, cancellationToken) : null;
                    var passwordVerified = user != null && user.HasPassword
                        && !string.IsNullOrWhiteSpace(user.PasswordHash)
                        && CryptoHelper.ValidateHash(currentPassword, user.PasswordHash);

                    if (!passwordVerified)
                    {
                        context.AddFailure(context.PropertyPath, "'Current password' is incorrect.");
                        return;
                    }

                    context.RootContextData[nameof(User)] = user;
                });

            RuleFor(_ => _.NewPassword)
                .NotEmpty()
                .MaximumLength(128)
                .Password()
                .NotEqual(_ => _.CurrentPassword, StringComparer.Ordinal);

            RuleFor(_ => _.ConfirmPassword)
                .NotEmpty()
                .MaximumLength(128)
                .Equal(_ => _.NewPassword, StringComparer.Ordinal);
        }
    }
}
