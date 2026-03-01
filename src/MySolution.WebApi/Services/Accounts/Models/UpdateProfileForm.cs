using FluentValidation;
using MySolution.WebApi.Libraries.Globalizer;
using MySolution.WebApi.Services.Accounts.Entities;

namespace MySolution.WebApi.Services.Accounts.Models
{
    public class UpdateProfileForm
    {
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? FullName { get; set; }
        public string? Bio { get; set; }
        public DateOnly? DateOfBirth { get; set; }
        public Gender? Gender { get; set; }
        public string? Country { get; set; }
        public string? Locale { get; set; }
    }

    public class UpdateProfileFormValidator : AbstractValidator<UpdateProfileForm>
    {
        public UpdateProfileFormValidator(IGlobalizer globalizer)
        {
            var currentYear = globalizer.Time.GetUtcNow().Year;
            var minimumAgeYears = 13;
            var maximumAgeYears = 150;
            var minimumBirthYear = currentYear - maximumAgeYears;
            var maximumBirthYear = currentYear - minimumAgeYears;

            RuleFor(x => x.FirstName)
                .NotEmpty()
                .MaximumLength(128)
                .When(x => x.FirstName != null, ApplyConditionTo.AllValidators);

            RuleFor(x => x.LastName)
                .NotEmpty()
                .MaximumLength(128)
                .When(x => x.LastName != null, ApplyConditionTo.AllValidators);

            RuleFor(x => x.FullName)
                .NotEmpty()
                .MaximumLength(256)
                .When(x => x.FullName != null, ApplyConditionTo.AllValidators);

            RuleFor(x => x.Bio)
                .NotEmpty()
                .MaximumLength(500)
                .When(x => x.Bio != null, ApplyConditionTo.AllValidators);

            RuleFor(x => x.Country)
                .NotEmpty()
                .MaximumLength(2)
                .When(x => x.Country != null, ApplyConditionTo.AllValidators);

            RuleFor(x => x.Locale)
                .NotEmpty()
                .MaximumLength(10)
                .When(x => x.Locale != null, ApplyConditionTo.AllValidators);

            RuleFor(x => x.Gender)
                .IsInEnum()
                .When(x => x.Gender != null, ApplyConditionTo.AllValidators);

            RuleFor(x => x.DateOfBirth!.Value.Year)
                .GreaterThanOrEqualTo(currentYear - maximumAgeYears)
                .LessThanOrEqualTo(currentYear - minimumAgeYears)
                .When(x => x.DateOfBirth.HasValue, ApplyConditionTo.AllValidators);
        }
    }
}