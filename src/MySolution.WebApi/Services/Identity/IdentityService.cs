using MySolution.WebApi.Data;

namespace MySolution.WebApi.Services.Identity
{
    public class IdentityService : IIdentityService
    {
        private readonly DefaultDbContext _dbContext;

        public IdentityService(DefaultDbContext dbContext)
        {
            _dbContext = dbContext;
        }
    }

    public interface IIdentityService
    {
    }
}
