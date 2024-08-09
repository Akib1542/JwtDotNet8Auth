using IdentityManagerServerApi.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Shared.Contracts.Interfaces;
using Shared.DTOs;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using static Shared.DTOs.ServiceResponses;

namespace IdentityManagerServerApi.Repositories
{
    public class UserAccount : IUserAccount
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        public UserAccount(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager = null, IConfiguration configuration = null)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        public async Task<GeneralResponse> CreateAccount(UserDTO userDTO)
        {
            if (userDTO == null) return new GeneralResponse(false,"Model is empty!");
            var newUser = new ApplicationUser()
            {
                Name = userDTO.Name,
                Email = userDTO.Email,
                PasswordHash = userDTO.Password,
                UserName = userDTO.Email
            };



            var user = await _userManager.FindByEmailAsync(newUser.Email);
            if(user != null) return new GeneralResponse(false, "User Registered Already!");

            var createUser = await _userManager.CreateAsync(newUser!, userDTO.Password);
            if (!createUser.Succeeded) return new GeneralResponse(false, "Error Occured, Please try again!");



            // Assign default role: Admin to first register, rest is user
            var checkAdmin = await _roleManager.FindByNameAsync("Admin");
            if (checkAdmin == null)
            {
                await _roleManager.CreateAsync(new IdentityRole() { Name = "Admin" });
                await _userManager.AddToRoleAsync(newUser, "Admin");
                return new GeneralResponse(true, "Account Created!");
            }
            else
            {
                var checkUser = await _roleManager.FindByNameAsync("User");
                if (checkUser == null)
                {
                    await _roleManager.CreateAsync(new IdentityRole() { Name = "User" });
                }
                await _userManager.AddToRoleAsync(newUser, "User");
                return new GeneralResponse(true, "Account Created");
            }
        }

        public async Task<LoginResponse> LoginAccount(LoginDTO loginDTO)
        {
            if(loginDTO == null)
            {
                return new LoginResponse(false, null!, "Login container is empty!");
            }
            var getUser = await _userManager.FindByEmailAsync(loginDTO.Email);
            if (getUser == null)
            {
                return new LoginResponse(false, null!, "User not found!");
            }
            bool checkUserPass = await _userManager.CheckPasswordAsync(getUser, loginDTO.Password);
            if (!checkUserPass)
            {
                return new LoginResponse(false, null!, "Invalid Email / Pass!");
            }

            var getUserRole = await _userManager.GetRolesAsync(getUser);
            var userSession = new UserSession(getUser.Id, getUser.Name, getUser.Email, getUserRole.First());
            string token = GenerateToken(userSession);
            return new LoginResponse(true, token!, "Login Completed!");
        }

        private string GenerateToken(UserSession userSession) {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var userClaims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, userSession.Id),
                new Claim(ClaimTypes.Name, userSession.Name),
                new Claim(ClaimTypes.Email, userSession.Email),
                new Claim(ClaimTypes.Role, userSession.Role)
            };

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: userClaims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: credentials
                );
            return new JwtSecurityTokenHandler().WriteToken(token); 
        }

    }
}
