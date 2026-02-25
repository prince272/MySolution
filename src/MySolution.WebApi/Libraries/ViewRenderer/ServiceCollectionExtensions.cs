using Microsoft.AspNetCore.Mvc.Razor;

namespace MySolution.WebApi.Libraries.ViewRenderer
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddViewRenderer(this IServiceCollection services)
        {
            services.AddHttpContextAccessor();
            services.AddMvcCore().AddRazorViewEngine();
            services.Configure<RazorViewEngineOptions>(o =>
            {
                o.ViewLocationFormats.Add("/Templates/{1}/{0}" + RazorViewEngine.ViewExtension);
                o.ViewLocationFormats.Add("/Templates/{0}" + RazorViewEngine.ViewExtension);
            });
            services.AddScoped<IViewRenderer, DefaultViewRenderer>();
            return services;
        }
    }
}
