using IdentityManagerServerApi.Data;
using Microsoft.AspNetCore.Identity;
using Shared.Contracts.Interfaces;
using Shared.DTOs;

namespace IdentityManagerServerApi.Repositories
{
    public class UserAccount : IUserAccount
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityUser> _roleManager;
        private readonly IConfiguration _configuration;
        public UserAccount(UserManager<ApplicationUser> userManager, RoleManager<IdentityUser> roleManager = null, IConfiguration configuration = null)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        public Task<ServiceResponses.GeneralResponse> CreateAccount(UserDTO userDTO)
        {
            throw new NotImplementedException();
        }

        public Task<ServiceResponses.LoginResponse> LoginAccount(LoginDTO loginDTO)
        {
            throw new NotImplementedException();
        }
    }
}
