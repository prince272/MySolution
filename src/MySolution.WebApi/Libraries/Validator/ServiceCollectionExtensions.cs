using FluentValidation;
using Humanizer;
using System.Reflection;

namespace MySolution.WebApi.Libraries.Validator
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddValidators(this IServiceCollection services)
        {
            services.AddScoped<Libraries.Validator.IValidator, DefaultValidator>();

            ValidatorOptions.Global.DefaultClassLevelCascadeMode = CascadeMode.Continue;
            ValidatorOptions.Global.DefaultRuleLevelCascadeMode = CascadeMode.Stop;
            ValidatorOptions.Global.DisplayNameResolver = (type, memberInfo, expression) =>
            {
                string? RelovePropertyName()
                {
                    if (expression != null)
                    {
                        var chain = FluentValidation.Internal.PropertyChain.FromExpression(expression);
                        if (chain.Count > 0) return chain.ToString();
                    }

                    if (memberInfo != null)
                    {
                        return memberInfo.Name;
                    }

                    return null;
                }

                return RelovePropertyName()?.Humanize();
            };

            var assemblies = new[] { Assembly.GetExecutingAssembly() };
            var validatorTypes = assemblies
                .SelectMany(a => a.DefinedTypes)
                .Select(t => t.AsType())
                .Where(type => type.IsClass
                    && !type.IsAbstract
                    && !type.IsGenericType
                    && type.GetInterfaces().Any(i => i.IsGenericType && i.GetGenericTypeDefinition() == typeof(FluentValidation.IValidator<>)))
                .ToArray();

            foreach (var concreteType in validatorTypes)
            {
                var matchingInterfaceType = concreteType.GetInterfaces()
                    .FirstOrDefault(i => i.IsGenericType && i.GetGenericTypeDefinition() == typeof(FluentValidation.IValidator<>));

                if (matchingInterfaceType != null)
                {
                    services.AddScoped(matchingInterfaceType, concreteType);
                }
            }

            return services;
        }
    }
}
