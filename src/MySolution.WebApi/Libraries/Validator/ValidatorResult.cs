using MySolution.WebApi.Helpers;
using System.Collections.Concurrent;
using System.Linq.Expressions;

namespace MySolution.WebApi.Libraries.Validator
{
    public class ValidatorResult<T>
    {
        private readonly ConcurrentDictionary<string, string[]> _errors;
        public IReadOnlyDictionary<string, object> ContextData { get; }

        public ValidatorResult()
        {
            _errors = new();
            ContextData = new Dictionary<string, object>();
        }

        public ValidatorResult(Dictionary<string, string[]> existingErrors, Dictionary<string, object> contextData)
        {
            _errors = new(existingErrors);
            ContextData = contextData;
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
    }
}