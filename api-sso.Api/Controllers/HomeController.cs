using api_sso.Api.Helpers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace api_sso.Api.Controllers
{
    public class HomeController : Controller
    {
        private readonly SignInManager<IdentityUser> _signInManager;

        public HomeController(SignInManager<IdentityUser> signInManager)
        {
            _signInManager = signInManager;
        }

        // Exibe a página inicial após login.
        [Authorize]
        public IActionResult Index()
        {
            // Pegando informações do usuário logado
            ClaimsIdentity? claimsIdentity = User.Identity as ClaimsIdentity;
            IEnumerable<Claim>? claims = claimsIdentity?.Claims;

            // Verifica se o login foi por um provedor externo (Microsoft)
            string? loginProvider = claims?.FirstOrDefault(c => c.Type == "Provider")?.Value;

            // Pega o JWT armazenado no cookie (se existir)
            string? jwtToken = claims?.FirstOrDefault(c => c.Type == "JWTToken")?.Value;
            string jwtTokenInfo = string.Empty;

            List<string> providers = new()
            {
                "Microsoft",
                "Internal (Local)"
            };


            bool isJwtToken = jwtToken != null && !providers.Contains(loginProvider);

            if (!string.IsNullOrEmpty(jwtToken))
            {
                // Decodificar o JWT para extrair informações
                JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                JwtSecurityToken token = handler.ReadJwtToken(jwtToken);
                jwtTokenInfo = $"JWT Token Expires: {token.ValidTo.ToString("dd/MM/yyyy")}";
            }

            // Determina o tipo de login com base nas informações disponíveis
            string loginType;

            if (isJwtToken)
            {
                // Login via OpenIddict (JWT token presente)
                loginType = "OpenIddict (JWT)";
            }
            else if (!string.IsNullOrEmpty(loginProvider) && loginProvider == "Microsoft")
            {
                // Login via provedor externo (Microsoft)
                loginType = "External (Microsoft)";
            }
            else
            {
                // Login local (ASP.NET Core Identity)
                loginType = "Internal (Local)";
            }

            // Passa os dados para a View
            ViewData["UserName"] = claimsIdentity?.Name;
            ViewData["LoginProvider"] = loginType;
            ViewData["LoginTime"] = DateTimeHelper.ReturnDateTimeNow().ToString("dd/MM/yyyy");
            ViewData["TokenInfo"] = jwtTokenInfo;

            return View();
        }

        // POST: Account/Logout
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Login", "Account");
        }
    }
}