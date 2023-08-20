using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace jwtauthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        public AuthenticateController(IConfiguration configuration)
        {
            _configuration = configuration;
        }


        [HttpPost]
        public async Task<IActionResult> Get([FromBody] LoginModel loginModel)
        {
            if (loginModel.username == null || loginModel.password == null)
            {
                return BadRequest("Username and password are required!");
            }



            if(loginModel.username != "Admin" && loginModel.password != "Admin") 
                return Unauthorized();
       

            var token = GenerateToken(loginModel.username);


            return StatusCode(200, new { message = "Success", token = token });
        }

        private string GenerateToken(string userName)
        {
            try
            {

                List<Claim> claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name,userName)
                };


                var key = new SymmetricSecurityKey(System.Text.Encoding.ASCII.GetBytes(
                        _configuration["ApiKey"]
                    ));


                var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

                var token = new JwtSecurityToken(
                        claims: claims,
                        expires: DateTime.Now.AddDays(1),

                        signingCredentials: cred,
                        issuer: _configuration["Jwt:Issuer"]
                    );


                var tokenHandler = new JwtSecurityTokenHandler();
                var jwt = tokenHandler.WriteToken(token);

                return jwt;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

    }


    public class LoginModel
    {

        public string username { get; set; }
        public string password { get; set; }
    }
}
