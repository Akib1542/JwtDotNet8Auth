using Shared.DTOs;
using static Shared.DTOs.ServiceResponses;

namespace Shared.Contracts.Interfaces
{
    public interface IUserAccount
    {
        Task<GeneralResponse> CreateAccount(UserDTO userDTO);
        Task<LoginResponse> LoginAccount(LoginDTO loginDTO);
    }
}
