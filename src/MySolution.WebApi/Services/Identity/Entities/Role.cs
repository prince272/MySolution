namespace MySolution.WebApi.Services.Identity.Entities
{
    public class Role
    {
        public Guid Id { get; set; }

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
