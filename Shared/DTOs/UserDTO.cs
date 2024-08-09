using System.ComponentModel.DataAnnotations;

namespace Shared.DTOs
{
    public class UserDTO
    {
        public string? Id { get; set; }
        [Required]
        public string Name { get; set; }

        [Required]
        [EmailAddress]
        [DataType(DataType.EmailAddress)]
        public string EmailAddress { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        [Compare(nameof(Password))]
        public string PasswordHash { get; set; } = string.Empty;

    }
}
