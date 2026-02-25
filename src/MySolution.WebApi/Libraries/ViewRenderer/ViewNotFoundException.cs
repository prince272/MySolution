namespace MySolution.WebApi.Libraries.ViewRenderer
{
    public sealed class ViewNotFoundException : Exception
    {
        public string ViewName { get; }
        public IEnumerable<string> SearchedLocations { get; }

        public ViewNotFoundException(string viewName, IEnumerable<string> searchedLocations)
            : base($"View '{viewName}' was not found. Searched locations:{Environment.NewLine}" +
                   string.Join(Environment.NewLine, searchedLocations.Select(l => $"  • {l}")))
        {
            ViewName = viewName;
            SearchedLocations = searchedLocations;
        }
    }
}
