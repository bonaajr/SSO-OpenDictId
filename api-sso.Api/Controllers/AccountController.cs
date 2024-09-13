using api_sso.Api.Helpers;
using api_sso.Api.ViewModels;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;

namespace api_sso.Api.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IOpenIddictTokenManager _openIddictTokenManager;

        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IOpenIddictTokenManager openIddictTokenManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _openIddictTokenManager = openIddictTokenManager;
        }

        // GET: Account/Login
        [HttpGet]
        public IActionResult Login()
            => View();

        // POST: Account/Login
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");

            if (ModelState.IsValid)
            {
                IdentityUser? user = model.Credencial.Contains("@") ? await _userManager.FindByEmailAsync(model.Credencial)
                                                                    : await _userManager.FindByNameAsync(model.Credencial);

                if (user != null)
                {
                    SignInResult result = await _signInManager.PasswordSignInAsync(user.UserName, 
                                                                                   model.Password, 
                                                                                   model.RememberMe, 
                                                                                   lockoutOnFailure: false);

                    if (result.Succeeded)
                    {
                        await _signInManager.SignInWithClaimsAsync(user, isPersistent: false, GenerateClaims(user, false));
                        return RedirectToAction(nameof(HomeController.Index), "Home");
                    }

                    ModelState.AddModelError(string.Empty, "Tentativa de login inválida. Verifique suas credenciais.");
                }

                return RedirectToAction("Register", "Account", new { UserName = model.Credencial, Password = model.Password });
            }

            return View(model);
        }

        private List<Claim> GenerateClaims(IdentityUser? user, bool isExternalLogin, ExternalLoginInfo? info = null)
            => new()
            {
                new Claim("JWTToken", GenerateJwtToken(user)),
                new Claim("Provider", isExternalLogin ?  info.LoginProvider : "Internal (Local)")
            };


        // GET: Account/Register
        [HttpGet]
        public IActionResult Register(string email, string password)
            => View(new RegisterViewModel() { Email = email, Password = password });


        // POST: Account/Register
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, string returnUrl = null)
        {
            bool isExternal = false;
            returnUrl = returnUrl ?? Url.Content("~/");
            
            if (ModelState.IsValid)
            {
                // Obter as informações de login externo do usuário (se houver)
                ExternalLoginInfo info = await _signInManager.GetExternalLoginInfoAsync();

                // Crie o usuário com os dados do formulário
                IdentityUser user = new IdentityUser { UserName = model.UserName, Email = model.Email };

                // Tentar criar o usuário com a senha fornecida
                IdentityResult result = await _userManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    // Associar o login externo ao novo usuário
                    if (info != null)
                    {
                        isExternal = true;
                        result = await _userManager.AddLoginAsync(user, info);
                    }

                    if (result.Succeeded)
                    {
                        // Login com o novo usuário criado
                        await _signInManager.SignInWithClaimsAsync(user, isPersistent: false, GenerateClaims(user, isExternal, info));
                        return RedirectToAction(nameof(HomeController.Index), "Home");
                    }
                }

                // Em caso de erro, exibir as mensagens de erro
                foreach (IdentityError error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }

            // Se algo deu errado, retorne o formulário com os erros
            return View(model);
        }

        // GET: Account/LoginWithMicrosoft
        [HttpGet]
        public IActionResult LoginWithMicrosoft(string returnUrl = null)
        {
            string? redirectUrl = Url.Action(nameof(ExternalLoginCallback), "Account", new { ReturnUrl = returnUrl });
            AuthenticationProperties properties = _signInManager.ConfigureExternalAuthenticationProperties("Microsoft", redirectUrl);
            return Challenge(properties, "Microsoft");
        }

        // Callback para login externo
        public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");

            if (remoteError != null)
            {
                ModelState.AddModelError(string.Empty, $"Error from external provider: {remoteError}");
                return View(nameof(Login));
            }

            ExternalLoginInfo? info = await _signInManager.GetExternalLoginInfoAsync();

            if (info == null)
                return RedirectToAction(nameof(Login));

            SignInResult result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);

            if (result.Succeeded)
            {
                IdentityUser? user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
                await _signInManager.SignInWithClaimsAsync(user, isPersistent: false, GenerateClaims(user, true, info));

                return RedirectToAction(nameof(HomeController.Index), "Home");
            }

            return View("Register", new RegisterViewModel { Email = info.Principal.FindFirstValue(ClaimTypes.Email) });
        }

        private string GenerateJwtToken(IdentityUser user)
        {
            JwtSecurityTokenHandler tokenHandler = new();
            byte[] key = Encoding.ASCII.GetBytes("xNutm212LHRJ0VoJ9/Kj+4akK6zgvP5x+lJWMDy3mV0n");
            DateTime dateTimeNow = DateTimeHelper.ReturnDateTimeNow();
            SecurityTokenDescriptor tokenDescriptor = new()
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                    new Claim(JwtRegisteredClaimNames.Email, user.Email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                }),
                IssuedAt = dateTimeNow,
                Expires = dateTimeNow.AddDays(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}