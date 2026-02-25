using System.ComponentModel.DataAnnotations;

namespace MySolution.WebApi.Libraries.Validator
{
    public class DefaultValidator : IValidator
    {
        private readonly IServiceProvider _serviceProvider;

        public DefaultValidator(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        public async Task<ValidatorResult> ValidateAsync<TModel>(TModel model, CancellationToken ct = default)
        {
            ArgumentNullException.ThrowIfNull(model, nameof(model));

            var errors = new Dictionary<string, List<string>>();

            // ✅ DataAnnotations validation
            CollectAnnotationErrors(model, errors);

            // ✅ FluentValidation (optional)
            await CollectFluentErrorsAsync(_serviceProvider, model, errors, ct);

            return new ValidatorResult
            {
                Errors = errors.ToDictionary(k => k.Key, v => v.Value.ToArray())
            };
        }

        private static void CollectAnnotationErrors<TModel>(TModel model, Dictionary<string, List<string>> errors)
        {
            var context = new ValidationContext(model!);
            var results = new List<System.ComponentModel.DataAnnotations.ValidationResult>();

            System.ComponentModel.DataAnnotations.Validator.TryValidateObject(
                model!,
                context,
                results,
                validateAllProperties: true
            );

            foreach (var result in results)
            {
                var members = result.MemberNames != null && result.MemberNames.Any()
                    ? result.MemberNames
                    : new[] { string.Empty };

                foreach (var member in members)
                {
                    if (!errors.TryGetValue(member, out var list))
                        errors[member] = list = [];

                    list.Add(result.ErrorMessage ?? "Validation error.");
                }
            }
        }

        private static async Task CollectFluentErrorsAsync<TModel>(
            IServiceProvider serviceProvider,
            TModel model,
            Dictionary<string, List<string>> errors,
            CancellationToken ct)
        {
            var fluentValidator = serviceProvider.GetService<FluentValidation.IValidator<TModel>>();

            if (fluentValidator != null)
            {
                var fluentResult = await fluentValidator.ValidateAsync(model, ct);

                foreach (var failure in fluentResult.Errors)
                {
                    var key = failure.PropertyName ?? string.Empty;

                    if (!errors.TryGetValue(key, out var list))
                        errors[key] = list = [];

                    list.Add(failure.ErrorMessage);
                }
            }
        }
    }
}