using FluentValidation;
using Humanizer;
using Microsoft.Extensions.Options;
using MySolution.WebApi.Helpers;
using MySolution.WebApi.Libraries.Globalizer;
using MySolution.WebApi.Libraries.Validator;
using MySolution.WebApi.Services.Accounts.Entities;
using MySolution.WebApi.Services.Accounts.Repositories;

namespace MySolution.WebApi.Services.Accounts.Models
{
    public record SignInForm
    {
        public string Username { get; set; } = null!;
        public string Password { get; set; } = null!;
    }

    public class SignInFormValidator : AbstractValidator<SignInForm>
    {
        public SignInFormValidator(IGlobalizer globalizer, IUserRepository userRepository, IOptions<AccountServiceOptions> options)
        {
            var currentRegionCode = globalizer.Region.TwoLetterISORegionName.ToUpperInvariant();

            RuleFor(_ => _.Username)
                .NotEmpty()
                .MaximumLength(128)
                .Username(currentRegionCode)
                .CustomAsync(async (username, context, cancellationToken) =>
                {
                    var user = await userRepository.GetByEmailOrPhoneAsync(username, cancellationToken);

                    if (user == null)
                    {
                        context.AddFailure(context.PropertyPath, $"'{StringParser.ParseContactType(username).Humanize()}' does not exist.");
                        return;
                    }

                    if (options.Value.Lockout.Enabled)
                    {
                        var now = globalizer.Time.GetUtcNow();
                        if (user.LockoutEndAt.HasValue && user.LockoutEndAt.Value > now)
                        {
                            var remaining = user.LockoutEndAt.Value - now;
                            context.AddFailure(context.PropertyPath, $"Account is locked. Try again in {remaining.Humanize(precision: 2, minUnit: TimeUnit.Second)}.");
                            return;
                        }
                    }

                    context.RootContextData[nameof(User)] = user;
                });

            RuleFor(_ => _.Password)
                .NotEmpty()
                .MaximumLength(128)
                .CustomAsync(async (password, context, cancellationToken) =>
                {
                    var user = context.RootContextData.TryGetValue(nameof(User), out var value) ? value as User : null;
                    var passwordVerified = !string.IsNullOrWhiteSpace(user?.PasswordHash)
                        && CryptoHelper.ValidateHash(password, user.PasswordHash);

                    if (!passwordVerified)
                    {
                        context.AddFailure(context.PropertyPath, "Password is incorrect.");

                        if (user != null && options.Value.Lockout.Enabled)
                        {
                            user.AccessFailedCount++;

                            if (user.AccessFailedCount >= options.Value.Lockout.MaxFailedAttempts)
                            {
                                user.LockoutEndAt = globalizer.Time.GetUtcNow().Add(options.Value.Lockout.Duration);
                                user.AccessFailedCount = 0;
                            }

                            await userRepository.UpdateAsync(user, cancellationToken);
                        }
                    }
                    else
                    {
                        if (user != null && options.Value.Lockout.Enabled && (user.AccessFailedCount > 0 || user.LockoutEndAt.HasValue))
                        {
                            user.AccessFailedCount = 0;
                            user.LockoutEndAt = null;
                            await userRepository.UpdateAsync(user, cancellationToken);
                        }
                    }
                });
        }
    }
}