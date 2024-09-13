using api_sso.Api.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Configura��o do banco de dados com SQL Server
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
    options.UseOpenIddict(); // Configura o OpenIddict com o Entity Framework Core
});

// Configura��es do Identity (usa esquema de autentica��o de cookies por padr�o)
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// Configura o OpenIddict
builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore().UseDbContext<ApplicationDbContext>();
    })
    .AddServer(options =>
    {
        options.AllowAuthorizationCodeFlow()
               .AllowImplicitFlow()
               .AllowPasswordFlow()
               .AllowRefreshTokenFlow();

        options.SetAuthorizationEndpointUris("/connect/authorize")
               .SetTokenEndpointUris("/connect/token")
               .SetLogoutEndpointUris("/connect/logout");

        options.RegisterScopes(OpenIddictConstants.Scopes.Email, OpenIddictConstants.Scopes.Profile, OpenIddictConstants.Scopes.OpenId);

        options.UseAspNetCore()
               .EnableAuthorizationEndpointPassthrough()
               .EnableTokenEndpointPassthrough()
               .EnableLogoutEndpointPassthrough();

        options.AddEphemeralEncryptionKey().AddEphemeralSigningKey(); // Em produ��o, utilize uma chave persistente
    })
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });

// Configura��es de Autentica��o para Cookies e JWT
builder.Services.AddAuthentication(options =>
{
    // Define o esquema padr�o como Identity.Application (j� gerido pelo Identity)
    options.DefaultAuthenticateScheme = IdentityConstants.ApplicationScheme;
    //options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme; // Usar JWT para challenge em APIs
})
.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
{
    // Configura��es de valida��o do JWT
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        // Adicione a chave de assinatura que voc� est� usando para gerar os tokens JWT
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("xNutm212LHRJ0VoJ9/Kj+4akK6zgvP5x+lJWMDy3mV0n")) // Substitua pela sua chave secreta
    };
})
.AddMicrosoftAccount(microsoftOptions =>
{
    microsoftOptions.ClientId = builder.Configuration["Authentication:Microsoft:ClientId"];
    microsoftOptions.ClientSecret = builder.Configuration["Authentication:Microsoft:ClientSecret"];
    microsoftOptions.SaveTokens = true;
});

// Adiciona suporte para controllers com views
builder.Services.AddControllersWithViews();

// Constru��o do app
var app = builder.Build();

// Habilitar p�gina de erro detalhada no modo de desenvolvimento
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

// Certifique-se de que a ordem dos middlewares est� correta
app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// Configurar autentica��o e autoriza��o
app.UseAuthentication();
app.UseAuthorization();

// Mapeia as rotas de controllers
app.MapDefaultControllerRoute();

app.Run();