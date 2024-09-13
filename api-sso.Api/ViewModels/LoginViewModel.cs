using System.ComponentModel.DataAnnotations;

namespace api_sso.Api.ViewModels
{
    public class LoginViewModel
    {
        [Required]
        public string Credencial { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Display(Name = "Remember me?")]
        public bool RememberMe { get; set; }
    }
}