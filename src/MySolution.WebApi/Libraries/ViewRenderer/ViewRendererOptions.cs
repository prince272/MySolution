namespace MySolution.WebApi.Libraries.ViewRenderer
{

    public sealed class ViewRendererOptions
    {
        public IDictionary<string, object?>? RouteValues { get; init; }
        public IDictionary<string, object?>? ViewData { get; init; }
    }
}
