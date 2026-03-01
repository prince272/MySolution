using MySolution.WebApi.Helpers;
using System.Collections.Concurrent;
using System.Linq.Expressions;

namespace MySolution.WebApi.Libraries.Validator
{
    public class ValidatorResult<T>
    {
        private readonly ConcurrentDictionary<string, string[]> _errors;

        public ValidatorResult()
        {
            _errors = new();
        }

        public ValidatorResult(Dictionary<string, string[]> existingErrors)
        {
            _errors = new(existingErrors);
        }

        public ValidatorResult(ValidatorResult<T> existingResult)
        {
            _errors = new(existingResult.Errors);
        }

        public bool IsValid => _errors.IsEmpty;

        public Dictionary<string, string[]> Errors => new(_errors);

        public bool ContainsErrorKey(Expression<Func<T, object?>> expression)
        {
            var propertyName = ExpressionHelper.GetText(expression, includeStart: false);
            return _errors.ContainsKey(propertyName);
        }

        public void AddError(Expression<Func<T, object?>> expression, string errorMessage)
        {
            var propertyName = ExpressionHelper.GetText(expression, includeStart: false);
            _errors.AddOrUpdate(
                propertyName,
                addValue: [errorMessage],
                updateValueFactory: (_, existing) => [.. existing, errorMessage]
            );
        }

        public async Task TryAddErrorAsync(
            Expression<Func<T, object?>> expression,
            T instance,
            Func<object?, CancellationToken, Task<bool>> conditionFunc,
            Func<object?, string> getErrorMessage,
            CancellationToken cancellationToken = default)
        {
            var value = expression.Compile()(instance);
            if (await conditionFunc(value, cancellationToken).ConfigureAwait(false))
            {
                AddError(expression, getErrorMessage(value));
            }
        }
    }
}