using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Linq.Expressions;
using System.Reflection;
using System.Text;

namespace MySolution.WebApi.Helpers
{
    public static class ExpressionHelper
    {
        public static string GetText(LambdaExpression expression, bool includeStart = true)
        {
            var unaryExpression = expression.Body as UnaryExpression;

            if (IsConversionToObject(unaryExpression))
            {
                return GetUncachedExpressionText(Expression.Lambda(
                    unaryExpression!.Operand,
                    expression.Parameters[0]), includeStart);
            }

            return GetUncachedExpressionText(expression, includeStart);
        }

        private static bool IsConversionToObject(UnaryExpression? expression)
        {
            return expression?.NodeType == ExpressionType.Convert &&
                expression.Operand?.NodeType == ExpressionType.MemberAccess &&
                expression.Type == typeof(object);
        }

        public static string GetUncachedExpressionText(LambdaExpression expression, bool includeStart = true)
            => GetExpressionText(expression, expressionTextCache: null, includeStart: includeStart);

        public static string GetExpressionText(LambdaExpression expression, ConcurrentDictionary<LambdaExpression, string>? expressionTextCache, bool includeStart = true)
        {
            ArgumentNullException.ThrowIfNull(expression, nameof(expression));

            if (expressionTextCache != null &&
                expressionTextCache.TryGetValue(expression, out var expressionText))
            {
                return expressionText;
            }

            var doNotCache = false;
            var length = 0;
            var segmentCount = 0;
            var trailingMemberExpressions = 0;

            var part = expression.Body;
            while (part != null)
            {
                switch (part.NodeType)
                {
                    case ExpressionType.Call:
                        doNotCache = true;

                        var methodExpression = (MethodCallExpression)part;
                        if (IsSingleArgumentIndexer(methodExpression))
                        {
                            length += "[99]".Length;
                            part = methodExpression.Object;
                            segmentCount++;
                            trailingMemberExpressions = 0;
                        }
                        else
                        {
                            part = null;
                        }
                        break;

                    case ExpressionType.ArrayIndex:
                        var binaryExpression = (BinaryExpression)part;

                        doNotCache = true;
                        length += "[99]".Length;
                        part = binaryExpression.Left;
                        segmentCount++;
                        trailingMemberExpressions = 0;
                        break;

                    case ExpressionType.MemberAccess:
                        var memberExpressionPart = (MemberExpression)part;
                        var name = memberExpressionPart.Member.Name;

                        if (name.Contains("__"))
                        {
                            part = null;
                        }
                        else
                        {
                            length += name.Length + 1;
                            part = memberExpressionPart.Expression;
                            segmentCount++;
                            trailingMemberExpressions++;
                        }
                        break;

                    case ExpressionType.Parameter:
                        part = null;
                        break;

                    default:
                        part = null;
                        break;
                }
            }

            if (trailingMemberExpressions > 0)
            {
                length--;
            }

            Debug.Assert(segmentCount >= 0);

            // If not including the start, we drop the outermost (last walked) segment
            var effectiveSegmentCount = !includeStart && segmentCount > 1 ? segmentCount - 1 : segmentCount;

            if (effectiveSegmentCount == 0)
            {
                Debug.Assert(!doNotCache);
                expressionTextCache?.TryAdd(expression, string.Empty);

                return string.Empty;
            }

            var builder = new StringBuilder(length);
            part = expression.Body;
            var remainingSegments = effectiveSegmentCount;
            while (part != null && remainingSegments > 0)
            {
                remainingSegments--;
                switch (part.NodeType)
                {
                    case ExpressionType.Call:
                        Debug.Assert(doNotCache);
                        var methodExpression = (MethodCallExpression)part;

                        InsertIndexerInvocationText(builder, methodExpression.Arguments.Single(), expression);

                        part = methodExpression.Object;
                        break;

                    case ExpressionType.ArrayIndex:
                        Debug.Assert(doNotCache);
                        var binaryExpression = (BinaryExpression)part;

                        InsertIndexerInvocationText(builder, binaryExpression.Right, expression);

                        part = binaryExpression.Left;
                        break;

                    case ExpressionType.MemberAccess:
                        var memberExpression = (MemberExpression)part;
                        var name = memberExpression.Member.Name;
                        Debug.Assert(!name.Contains("__"));

                        builder.Insert(0, name);
                        if (remainingSegments > 0)
                        {
                            builder.Insert(0, '.');
                        }

                        part = memberExpression.Expression;
                        break;

                    default:
                        Debug.Assert(false);
                        break;
                }
            }

            Debug.Assert(remainingSegments == 0);
            expressionText = builder.ToString();

            if (expressionTextCache != null && !doNotCache)
            {
                expressionTextCache.TryAdd(expression, expressionText);
            }

            return expressionText;
        }

        private static void InsertIndexerInvocationText(
            StringBuilder builder,
            Expression indexExpression,
            LambdaExpression parentExpression)
        {
            ArgumentNullException.ThrowIfNull(builder, nameof(builder));
            ArgumentNullException.ThrowIfNull(indexExpression, nameof(indexExpression));
            ArgumentNullException.ThrowIfNull(parentExpression, nameof(parentExpression));

            if (parentExpression.Parameters == null)
            {
                throw new ArgumentException(
                    $"The '{nameof(parentExpression.Parameters)}' property of '{nameof(parentExpression)}' cannot be null.");
            }

            var converted = Expression.Convert(indexExpression, typeof(object));
            var fakeParameter = Expression.Parameter(typeof(object), null);
            var lambda = Expression.Lambda<Func<object, object>>(converted, fakeParameter);
            Func<object, object> func;

            try
            {
                func = lambda.Compile();
            }
            catch (InvalidOperationException ex)
            {
                var parameters = parentExpression.Parameters.ToArray();
                var paramName = parameters.Length > 0 ? parameters[0].Name : "unknown";
                throw new InvalidOperationException(
                    $"The indexer expression '{indexExpression}' is not valid for parameter '{paramName}'.",
                    ex);
            }

            builder.Insert(0, ']');
            builder.Insert(0, Convert.ToString(func(null!), CultureInfo.InvariantCulture));
            builder.Insert(0, '[');
        }

        public static bool IsSingleArgumentIndexer(Expression expression)
        {
            if (expression is not MethodCallExpression methodExpression || methodExpression.Arguments.Count != 1)
            {
                return false;
            }

            var declaringType = methodExpression.Method.DeclaringType;
            if (declaringType == null)
            {
                return false;
            }

            var defaultMember = declaringType.GetCustomAttribute<DefaultMemberAttribute>(inherit: true);
            if (defaultMember == null)
            {
                return false;
            }

            var runtimeProperties = declaringType.GetRuntimeProperties();
            foreach (var property in runtimeProperties)
            {
                if (string.Equals(defaultMember.MemberName, property.Name, StringComparison.Ordinal) &&
                    property.GetMethod == methodExpression.Method)
                {
                    return true;
                }
            }

            return false;
        }
    }
}