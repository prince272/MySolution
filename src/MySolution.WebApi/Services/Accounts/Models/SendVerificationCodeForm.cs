using FluentValidation;
using MySolution.WebApi.Libraries.Globalizer;
using MySolution.WebApi.Libraries.Validator;

namespace MySolution.WebApi.Services.Accounts.Models
{
    /// <summary>
    /// Form for requesting a verification code to be sent to the user.
    /// </summary>
    public class SendVerificationCodeForm
    {
        /// <summary>
        /// Current username of the account requesting the verification code. Must be provided and cannot exceed 128 characters.
        /// </summary>
        public string CurrentUsername { get; set; } = null!;
        
        /// <summary>
        /// New username when the reason is for account change. Required only when Reason is ChangeAccount and cannot exceed 128 characters.
        /// </summary>
        public string NewUsername { get; set; } = null!;
        
        /// <summary>
        /// Reason for sending the verification code.
        /// </summary>
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
        public SendVerificationCodeFormValidator(IGlobalizer globalizer)
        {
            var currentRegionCode = globalizer.Region.TwoLetterISORegionName.ToUpperInvariant();

            RuleFor(_ => _.CurrentUsername).NotEmpty().MaximumLength(128).Username(currentRegionCode);

            RuleFor(_ => _.NewUsername)
                .NotEmpty()
                    .When(_ => _.Reason == VerificationCodeReason.ChangeAccount)
                .MaximumLength(128)
                    .When(_ => _.Reason == VerificationCodeReason.ChangeAccount)
                .Username(currentRegionCode)
                    .When(_ => _.Reason == VerificationCodeReason.ChangeAccount)
                .NotEqual(_ => _.CurrentUsername, StringComparer.OrdinalIgnoreCase)
                    .When(_ => _.Reason == VerificationCodeReason.ChangeAccount);
        }
    }
}