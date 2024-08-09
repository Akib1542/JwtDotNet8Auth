using Microsoft.AspNetCore.Mvc;
using Shared.Contracts.Interfaces;
using Shared.DTOs;

namespace IdentityManagerServerApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly IUserAccount userAccount;

        public AccountController(IUserAccount userAccount)
        {
            this.userAccount = userAccount;
        }

        [HttpPost("register")]
        public async Task<IActionResult>Register(UserDTO userDTO)
        {
            var response = await userAccount.CreateAccount(userDTO);
            return Ok(response);    
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginDTO loginDTO)
        {
            var response = await userAccount.LoginAccount(loginDTO);
            return Ok(response);
        }
    }
}
