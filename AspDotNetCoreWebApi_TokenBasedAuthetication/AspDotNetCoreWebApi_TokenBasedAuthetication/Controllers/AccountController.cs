using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AspDotNetCoreWebApi_TokenBasedAuthetication.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace AspDotNetCoreWebApi_TokenBasedAuthetication.Controllers
{
    [Authorize]
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private IConfiguration _config;

        public AccountController(IConfiguration config)
        {
            _config = config;
        }

        [AllowAnonymous]
        [HttpPost]
        public IActionResult Login([FromBody]UserModel login)
        {
            IActionResult response = Unauthorized();
            var user = AuthenticateUser(login);

            if (user != null)
            {
                var tokenString = GenerateJSONWebToken(user);
                response = Ok(new { token = tokenString });
            }

            return response;
        }


        // GET api/Account/Get
        [HttpGet]
        public ActionResult<IEnumerable<string>> Get()
        {
            return new string[] { "value1", "value2" };
        }

        //GET api/Account/GetUserRole
        [HttpGet(Name = "GetUserRole"), Authorize(Roles ="Admin")]
        public string GetUserRole()
        {
            string result = string.Empty;

            var user = HttpContext.User;

            var claims = user.Claims;


            if (user.HasClaim(x => x.Type == "Role"))
            {
                result = user.Claims.FirstOrDefault(x => x.Type == "Role").Value;
            }

            return result;
        }

        private string GenerateJSONWebToken(UserModel user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            List<Claim> claims = new List<Claim>();
            claims.Add(new Claim(JwtRegisteredClaimNames.GivenName, user.Username));
            claims.Add(new Claim("Role", user.Role));
            claims.Add(new Claim(JwtRegisteredClaimNames.Email, user.EmailAddress));

            var token = new JwtSecurityToken(_config["Jwt:Issuer"], _config["Jwt:Issuer"], claims, expires: DateTime.Now.AddMinutes(5), signingCredentials: credentials);
                    

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private UserModel AuthenticateUser(UserModel login)
        {
            //Autheticate the user from database
            UserModel model = null;
            if (login.Username.ToLower() == "admin" && login.EmailAddress.ToLower() == "admin@test.com")
            {
                model = new UserModel { Username = "Admin", EmailAddress = "admin@test.com",Role ="Admin" };
            }
            if (login.Username.ToLower() == "user" && login.EmailAddress.ToLower() == "user@test.com")
            {
                model = new UserModel { Username = "User", EmailAddress = "user@test.com", Role = "User" };
            }

            return model;
        }


    }

}