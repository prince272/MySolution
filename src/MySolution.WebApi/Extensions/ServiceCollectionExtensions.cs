using MySolution.WebApi.Services.Accounts;
using MySolution.WebApi.Services.Accounts.Repositories;

namespace MySolution.WebApi.Extensions
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddServices(this IServiceCollection services)
        {
            // Register your services here
            services.AddScoped<IAccountService, AccountService>();
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
