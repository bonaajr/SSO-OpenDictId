# SSO-OpenDictId
Este projeto é uma implementação de Single Sign-On (SSO) utilizando OpenIddict com suporte para autenticação externa, neste caso com login via Microsoft, além de autenticação baseada em JWT para proteger os endpoints da API. O projeto foi desenvolvido em ASP.NET Core, e também possui suporte para execução em Docker.

**Funcionalidades**
- SSO com OpenIddict: Implementa um servidor de autorização usando OpenIddict para autenticação e autorização.
- Login com Microsoft: Integração com Azure AD para autenticação externa usando contas Microsoft.
- Autenticação JWT: Geração de tokens JWT para controle de acesso em endpoints protegidos.
- Autenticação e Autorização: Utiliza ASP.NET Identity para gerenciamento de usuários e permissões.

**Tecnologias Utilizadas**
- ASP.NET Core 8
- OpenIddict para SSO e emissão de tokens.
- ASP.NET Identity para gerenciamento de usuários.
- JWT (JSON Web Token) para autenticação de APIs.
- Entity Framework Core para gerenciamento de dados.
- SQL Server como banco de dados.
- Docker para containerização da aplicação.

**Estrutura do Projeto**
- api-sso.Api: Contém a lógica principal da API, incluindo autenticação, autorização e emissão de tokens JWT.

**Controllers:**
- AccountController: Lida com o registro, login(geração do jwt) e logout de usuários.
- HomeController: Contém a lógica para a página inicial e proteção de rotas autenticadas.

**Views:**
- Login e Register: Páginas de autenticação para login e cadastro de novos usuários.

**Services:**
- Implementação de serviços para lidar com autenticação e geração de tokens.
- appsettings.json: Arquivo de configuração contendo parâmetros de conexão com o banco de dados e configuração do OpenIddict (incluindo secrets, quando necessário).

**Data:**
- ApplicationDbContext: Contexto do Entity Framework Core que gerencia a persistência de dados relacionados aos usuários e autenticações.
- Dockerfile: Arquivo de configuração do Docker para containerização da aplicação.

# Configuração
**Clone o repositório:**
- git clone https://github.com/bonaajr/SSO-OpenDictId.git
- Atualize o arquivo appsettings.json com as configurações adequadas:

**AzureAD:** 
- Configure o ClientId e ClientSecret obtidos no portal do Azure AD.
- ConnectionStrings: Atualize a string de conexão para o banco de dados SQL Server.

**Execute o projeto:**
- dotnet run

**Para rodar com Docker:**
- docker build -t sso-opendictid .
- docker run -p 5000:80 sso-opendictid
- Lembre-se que se for rodar um sql server em outro container, deve adicionar os dois a mesma network.
  
**Endpoints**
- /account/login: Página de login para o usuário.
- /account/register: Página de cadastro de novos usuários.
- /home: Página protegida que mostra detalhes do token JWT e local por onde foi feito o login.

**Integração com Azure AD**
Este projeto usa Azure Active Directory para login com contas Microsoft. Para configurar:

**Crie uma aplicação no portal Azure AD.**
- Obtenha o ClientId e o ClientSecret.
- Atualize o appsettings.json com esses valores.

**Como Contribuir**
Sinta-se à vontade para contribuir com este projeto. Basta abrir uma issue ou enviar um pull request.

**Licença**
Este projeto está licenciado sob a licença MIT. Veja o arquivo LICENSE para mais detalhes.
