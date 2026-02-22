using FluentValidation;
using Microsoft.AspNetCore.DataProtection.Repositories;
using MySolution.WebApi.Services.Identity;
using MySolution.WebApi.Services.Identity.Repositories;
using System.ComponentModel.DataAnnotations;
using System.Reflection;

namespace MySolution.WebApi.Extensions
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddServices(this IServiceCollection services)
        {
            // Register your services here
            services.AddScoped<IIdentityService, IdentityService>();
            return services;
        }

        public static IServiceCollection AddRepositories(this IServiceCollection services)
        {
            // Register your repositories here
            services.AddScoped<IUserRepository, UserRepository>();
            return services;
        }
    }
}
