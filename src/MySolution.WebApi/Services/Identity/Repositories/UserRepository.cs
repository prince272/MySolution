using Microsoft.EntityFrameworkCore;
using MySolution.WebApi.Data;
using MySolution.WebApi.Services.Identity.Entities;
namespace MySolution.WebApi.Services.Identity.Repositories
{
    public class UserRepository : IUserRepository
    {
        private readonly DefaultDbContext _dbContext;
        public UserRepository(DefaultDbContext dbContext)
        {
            _dbContext = dbContext;
        }
        public async Task AddAsync(User user, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(user, nameof(user));

            await _dbContext.Set<User>().AddAsync(user, cancellationToken);
            await _dbContext.SaveChangesAsync(cancellationToken);
        }
        public async Task UpdateAsync(User user, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(user, nameof(user));

            _dbContext.Set<User>().Update(user);
            await _dbContext.SaveChangesAsync(cancellationToken);
        }
        public async Task RemoveAsync(User user, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(user, nameof(user));

            _dbContext.Set<User>().Remove(user);
            await _dbContext.SaveChangesAsync(cancellationToken);
        }
        public async Task<User?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
        {
            return await _dbContext.Set<User>().Include(u => u.Roles)
                .FirstOrDefaultAsync(u => u.Id == id, cancellationToken);
        }
        public async Task<User?> GetByEmailOrPhoneAsync(string emailOrPhone, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(emailOrPhone, nameof(emailOrPhone));

            return await _dbContext.Set<User>()
                .FirstOrDefaultAsync(u => u.Email == emailOrPhone || u.PhoneNumber == emailOrPhone, cancellationToken);
        }
        public async Task<bool> ExistsByIdAsync(Guid id, CancellationToken cancellationToken = default)
        {
            return await _dbContext.Set<User>()
                .AnyAsync(u => u.Id == id, cancellationToken);
        }
        public async Task<bool> ExistsByEmailOrPhoneAsync(string emailOrPhone, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(emailOrPhone, nameof(emailOrPhone));

            return await _dbContext.Set<User>()
                .AnyAsync(u => u.Email == emailOrPhone || u.PhoneNumber == emailOrPhone, cancellationToken);
        }
        public async Task<bool> ExistsByUserNameAsync(string userName, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(userName, nameof(userName));

            return await _dbContext.Set<User>()
                .AnyAsync(u => u.UserName == userName, cancellationToken);
        }

        public async Task AddRolesAsync(User user, IEnumerable<RoleName> roleNames, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(user);
            ArgumentNullException.ThrowIfNull(roleNames);

            var roleSet = roleNames.ToHashSet();
            if (roleSet.Count == 0)
                return;

            // Load existing roles from DB
            var existingRoles = await _dbContext.Set<Role>()
                .Where(r => roleSet.Contains(r.Name))
                .ToListAsync(cancellationToken);

            var existingRoleNames = existingRoles
                .Select(r => r.Name)
                .ToHashSet();

            // Create missing roles
            var newRoles = roleSet
                .Where(r => !existingRoleNames.Contains(r))
                .Select(r => new Role
                {
                    Id = Guid.NewGuid(),
                    Name = r
                })
                .ToList();

            if (newRoles.Count > 0)
                await _dbContext.Set<Role>().AddRangeAsync(newRoles, cancellationToken);

            // Attach roles to user
            foreach (var role in existingRoles.Concat(newRoles))
            {
                if (!user.Roles.Any(r => r.Name == role.Name))
                    user.Roles.Add(role);
            }

            await _dbContext.SaveChangesAsync(cancellationToken);
        }

        public async Task RemoveRolesAsync(User user, IEnumerable<RoleName> roleNames, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(user);
            ArgumentNullException.ThrowIfNull(roleNames);

            var roleSet = roleNames.ToHashSet();
            if (roleSet.Count == 0)
                return;

            await _dbContext.Entry(user)
                .Collection(u => u.Roles)
                .LoadAsync(cancellationToken);

            var rolesToRemove = user.Roles
                .Where(r => roleSet.Contains(r.Name))
                .ToList();

            foreach (var role in rolesToRemove)
                user.Roles.Remove(role);

            await _dbContext.SaveChangesAsync(cancellationToken);
        }
    }

    public interface IUserRepository
    {
        Task AddAsync(User user, CancellationToken cancellationToken = default);
        Task UpdateAsync(User user, CancellationToken cancellationToken = default);
        Task RemoveAsync(User user, CancellationToken cancellationToken = default);
        Task<User?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);
        Task<User?> GetByEmailOrPhoneAsync(string emailOrPhone, CancellationToken cancellationToken = default);
        Task<bool> ExistsByIdAsync(Guid id, CancellationToken cancellationToken = default);
        Task<bool> ExistsByEmailOrPhoneAsync(string emailOrPhone, CancellationToken cancellationToken = default);
        Task<bool> ExistsByUserNameAsync(string userName, CancellationToken cancellationToken = default);
        Task AddRolesAsync(User user, IEnumerable<RoleName> roleNames, CancellationToken cancellationToken = default);
        Task RemoveRolesAsync(User user, IEnumerable<RoleName> roleNames, CancellationToken cancellationToken = default);
    }
}