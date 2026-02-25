using FluentValidation;

namespace MySolution.WebApi.Services.Accounts.Models
{
    /// <summary>
    /// Request form for sending a verification code to the user.
    /// </summary>
    public class SendVerificationCodeForm
    {
        /// <summary>
        /// The username (email or phone) of the account to send the verification code to.
        /// </summary>
        /// <example>john.doe@example.com</example>
        public string Username { get; set; } = null!;

        /// <summary>
        /// The new username to switch to. Required only when <see cref="Reason"/> is <see cref="VerificationCodeReason.ChangeAccount"/>, and must be omitted otherwise.
        /// </summary>
        /// <example>john.new@example.com</example>
        public string? NewUsername { get; set; }

        /// <summary>
        /// The reason the verification code is being requested. Determines validation rules and the action taken after successful verification.
        /// </summary>
        /// <example>VerifyAccount</example>
        public VerificationCodeReason Reason { get; set; }
    }

    /// <summary>
    /// Specifies the reason a verification code is being sent to the user.
    /// </summary>
    public enum VerificationCodeReason
    {
        /// <summary>
        /// The user is verifying their account for the first time after registration.
        /// </summary>
        VerifyAccount,

        /// <summary>
        /// The user is confirming a change to sensitive account details such as email or phone number.
        /// <see cref="SendVerificationCodeForm.NewUsername"/> must be provided in this case.
        /// </summary>
        ChangeAccount,

        /// <summary>
        /// The user has requested a password reset and needs to verify their identity before proceeding.
        /// </summary>
        ResetPassword,
    }

    public class SendVerificationCodeFormValidator : AbstractValidator<SendVerificationCodeForm>
    {
        public SendVerificationCodeFormValidator()
        {
            RuleFor(x => x.Username)
                .NotEmpty()
                .WithMessage("Username is required.");

            RuleFor(x => x.Reason)
                .IsInEnum()
                .WithMessage($"Reason must be one of: {string.Join(", ", Enum.GetNames<VerificationCodeReason>())}.");

            RuleFor(x => x.NewUsername)
                .NotEmpty()
                .When(x => x.Reason == VerificationCodeReason.ChangeAccount)
                .WithMessage("NewUsername is required when changing account.");

            RuleFor(x => x.NewUsername)
                .Null()
                .When(x => x.Reason != VerificationCodeReason.ChangeAccount)
                .WithMessage("NewUsername should only be provided when changing account.");
        }
    }
}