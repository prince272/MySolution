using FluentValidation;
using MySolution.WebApi.Libraries.JwtTokenProvider;
using MySolution.WebApi.Services.Accounts.Entities;
using MySolution.WebApi.Services.Accounts.Repositories;

namespace MySolution.WebApi.Services.Accounts.Models
{
    public class SignInWithRefreshTokenForm
    {
        public string RefreshToken { get; set; } = null!;
    }

    public class SignInWithRefreshTokenFormValidator : AbstractValidator<SignInWithRefreshTokenForm>
    {
        public SignInWithRefreshTokenFormValidator(IJwtTokenProvider jwtTokenProvider, IUserRepository userRepository)
        {
            RuleFor(_ => _.RefreshToken)
                .NotEmpty()
                .CustomAsync(async (refreshToken, context, cancellationToken) =>
                {
                    var claimsPrincipal = await jwtTokenProvider.ValidateRefreshTokenAsync(refreshToken, cancellationToken);
                    var userId = claimsPrincipal?.GetSubject();
                    var user = !string.IsNullOrWhiteSpace(userId)
                        ? await userRepository.GetByIdAsync(userId, cancellationToken)
                        : null;

                    if (user == null)
                    {
                        context.AddFailure(context.PropertyPath, "'Refresh token' is invalid.");
                        return;
                    }

                    context.RootContextData[nameof(User)] = user;
                });
        }
    }
}
