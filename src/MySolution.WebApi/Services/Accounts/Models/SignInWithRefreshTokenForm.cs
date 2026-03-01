using FluentValidation;

namespace MySolution.WebApi.Services.Accounts.Models
{
    /// <summary>
    /// Form for refreshing authentication tokens using a valid refresh token.
    /// </summary>
    public class SignInWithRefreshTokenForm
    {
        /// <summary>
        /// Valid refresh token to obtain new access and refresh tokens. Must be provided.
        /// </summary>
        public string RefreshToken { get; set; } = null!;
    }

    public class SignInWithRefreshTokenFormValidator : AbstractValidator<SignInWithRefreshTokenForm>
    {
        public SignInWithRefreshTokenFormValidator()
        {
            RuleFor(_ => _.RefreshToken).NotEmpty();
        }
    }
}
