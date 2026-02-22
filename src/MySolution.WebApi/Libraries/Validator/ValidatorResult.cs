using MySolution.WebApi.Helpers;
using System.Linq.Expressions;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace MySolution.WebApi.Libraries.Validator
{
    public class ValidatorResult
    {
        public bool IsValid => Errors.Count == 0;

        public Dictionary<string, string[]> Errors { get; set; } = new();

        public bool ContainsErrorKey(LambdaExpression expression)
        {
            var propertyName = ExpressionHelper.GetText(expression, includeStart: false);
            return Errors.ContainsKey(propertyName);
        }

        public void AddError(LambdaExpression expression, string errorMessage)
        {
            var propertyName = ExpressionHelper.GetText(expression, includeStart: false);

            if (!Errors.TryGetValue(propertyName, out var existing))
                Errors[propertyName] = [errorMessage];
            else
                Errors[propertyName] = [.. existing, errorMessage];
        }
    }
}
