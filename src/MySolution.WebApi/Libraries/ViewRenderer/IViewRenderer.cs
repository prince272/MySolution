namespace MySolution.WebApi.Libraries.ViewRenderer
{
    public interface IViewRenderer
    {
        Task<string> RenderAsync(string viewName, ViewRendererOptions? options = null, CancellationToken cancellationToken = default);
        Task<string> RenderAsync<TModel>(string viewName, TModel model, ViewRendererOptions? options = null, CancellationToken cancellationToken = default);
    }
}
