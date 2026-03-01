using FluentValidation;
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

        public async Task<ValidatorResult<TModel>> ValidateAsync<TModel>(TModel model, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(model, nameof(model));

            var errors = new Dictionary<string, List<string>>();
            var contextData = new Dictionary<string, object>();

            CollectAnnotationErrors(model, errors);
            await CollectFluentErrorsAsync(_serviceProvider, model, errors, contextData, cancellationToken);

            return new ValidatorResult<TModel>(
                errors.ToDictionary(k => k.Key, v => v.Value.ToArray()),
                contextData);
        }

        private static void CollectAnnotationErrors<TModel>(TModel model, Dictionary<string, List<string>> errors)
        {          
            ArgumentNullException.ThrowIfNull(model, nameof(model));
            ArgumentNullException.ThrowIfNull(errors, nameof(errors));

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

        private static async Task CollectFluentErrorsAsync<TModel>(IServiceProvider serviceProvider, TModel model, Dictionary<string, List<string>> errors, Dictionary<string, object> contextData, CancellationToken cancellationToken)
        {
            var fluentValidator = serviceProvider.GetService<FluentValidation.IValidator<TModel>>();
            if (fluentValidator != null)
            {
                var validationContext = new ValidationContext<TModel>(model);
                var fluentResult = await fluentValidator.ValidateAsync(validationContext, cancellationToken);

                foreach (var failure in fluentResult.Errors)
                {
                    var key = failure.PropertyName ?? string.Empty;
                    if (!errors.TryGetValue(key, out var list))
                        errors[key] = list = [];
                    list.Add(failure.ErrorMessage);
                }

                foreach (var kvp in validationContext.RootContextData)
                    contextData[kvp.Key] = kvp.Value;
            }
        }
    }
}