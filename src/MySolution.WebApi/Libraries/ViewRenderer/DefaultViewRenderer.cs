using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Mvc.ViewEngines;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace MySolution.WebApi.Libraries.ViewRenderer
{
    public sealed class DefaultViewRenderer : IViewRenderer
    {
        private readonly IRazorViewEngine _viewEngine;
        private readonly ITempDataProvider _tempDataProvider;
        private readonly IServiceProvider _serviceProvider;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public DefaultViewRenderer(
            IRazorViewEngine viewEngine,
            ITempDataProvider tempDataProvider,
            IServiceProvider serviceProvider,
            IHttpContextAccessor httpContextAccessor)
        {
            _viewEngine = viewEngine ?? throw new ArgumentNullException(nameof(viewEngine));
            _tempDataProvider = tempDataProvider ?? throw new ArgumentNullException(nameof(tempDataProvider));
            _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
            _httpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));
        }

        public Task<string> RenderAsync(string viewName, ViewRendererOptions? options = null, CancellationToken cancellationToken = default)
            => RenderAsync<object?>(viewName, null, options, cancellationToken);

        public async Task<string> RenderAsync<TModel>(
            string viewName,
            TModel model,
            ViewRendererOptions? options = null,
            CancellationToken cancellationToken = default)
        {
            options ??= new ViewRendererOptions();

            var httpContext = BuildHttpContext();
            var actionContext = BuildActionContext(httpContext, options);
            var view = ResolveView(actionContext, viewName);

            await using var writer = new StringWriter();

            var viewData = BuildViewData(model, options);
            var tempData = new TempDataDictionary(httpContext, _tempDataProvider);

            var viewContext = new ViewContext(
                actionContext,
                view,
                viewData,
                tempData,
                writer,
                new HtmlHelperOptions());

            await view.RenderAsync(viewContext);
            await writer.FlushAsync(cancellationToken);

            return writer.ToString();
        }

        private HttpContext BuildHttpContext()
        {
            if (_httpContextAccessor.HttpContext is { } ambient)
                return ambient;

            var context = new DefaultHttpContext { RequestServices = _serviceProvider };
            context.Request.Scheme = "https";
            context.Request.Host = new HostString("localhost");
            context.Request.Path = "/";
            return context;
        }

        private static ActionContext BuildActionContext(HttpContext httpContext, ViewRendererOptions options)
        {
            var routeData = new RouteData();
            routeData.Values["controller"] = "Home";
            routeData.Values["action"] = "Index";

            if (options.RouteValues is not null)
                foreach (var (k, v) in options.RouteValues)
                    routeData.Values[k] = v;

            return new ActionContext(httpContext, routeData, new ActionDescriptor());
        }

        private IView ResolveView(ActionContext actionContext, string viewName)
        {
            var absoluteResult = _viewEngine.GetView(executingFilePath: null, viewPath: viewName, isMainPage: true);
            if (absoluteResult.Success)
                return absoluteResult.View;

            var findResult = _viewEngine.FindView(actionContext, viewName, isMainPage: true);
            if (findResult.Success)
                return findResult.View;

            var searched = absoluteResult.SearchedLocations
                .Union(findResult.SearchedLocations)
                .Distinct();

            throw new ViewNotFoundException(viewName, searched);
        }

        private ViewDataDictionary BuildViewData<TModel>(TModel model, ViewRendererOptions options)
        {
            var modelMetadataProvider = _serviceProvider.GetRequiredService<IModelMetadataProvider>();

            var viewData = model is null
                ? new ViewDataDictionary(modelMetadataProvider, new ModelStateDictionary())
                : new ViewDataDictionary<TModel>(modelMetadataProvider, new ModelStateDictionary())
                {
                    Model = model
                };

            if (options.ViewData is not null)
                foreach (var (k, v) in options.ViewData)
                    viewData[k] = v;

            return viewData;
        }
    }
}