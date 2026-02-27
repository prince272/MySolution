namespace MySolution.WebApi.Services.Accounts.Entities
{
    public class Role
    {
        public string Id { get; set; } = null!;

        public RoleName Name { get; set; }

        public string? Description { get; set; }

        public ICollection<User> Users { get; set; } = [];
    }

    public enum RoleName
    {
        Admin,
        Editor,
        Moderator,
        Viewer
    }
}
