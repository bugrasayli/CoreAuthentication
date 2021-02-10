using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using WebApplication2.Model;

namespace WebApplication2.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class UserController : ControllerBase
    {
        private User UserModel;
        private IConfiguration config;
        public UserController(IConfiguration _config)
        {
            UserModel = new User();
            UserModel.Name = "Buğra";
            UserModel.Surname = "Şayli";
            UserModel.Email = "bugrasayli@gmail.com";
            UserModel.Password = "12345";
            this.config = _config;
        }

        [HttpPost]
        public string Post()
        {
            var Identity = HttpContext.User.Identity as ClaimsIdentity;
            IList<Claim> claim = Identity.Claims.ToList();
            var UserName = claim[0].Value;
            return "Welcome " + UserName;

        }
        [HttpGet]
        public IActionResult User(string Email, string Password)
        {
            User user = new User();
            user.Email = Email;
            user.Password = Password;
            IActionResult response = Unauthorized();
            var UserAut = AuthenticateUser(user);
            if (UserAut != null)
            {
                var tokenStr = GenerateJSONWebToken(UserAut);
                response = Ok(new { token = tokenStr });
            }
            return response;
        }
        private object GenerateJSONWebToken(User userAut)
        {
            var SecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]));
            var Credential = new SigningCredentials(SecurityKey, SecurityAlgorithms.HmacSha256);
            var Claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userAut.Name),
                new Claim(JwtRegisteredClaimNames.Email,userAut.Email),
                new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())
            };
            var token = new JwtSecurityToken(
               issuer: config["Jwt:Issuer"],
               audience: config["Jwt:Issuer"],
               Claims,
               expires: DateTime.Now.AddMinutes(120),
               signingCredentials: Credential
                );
            var EncodeToken = new JwtSecurityTokenHandler().WriteToken(token);
            return EncodeToken;
            throw new NotImplementedException();
        }
        private User AuthenticateUser(User _user)
        {
            User user = new Model.User();
            if (_user.Email == null || _user.Password == null)
            {
                return null;
            }
            if (_user.Email.Equals(this.UserModel.Email) && _user.Password.Equals(this.UserModel.Password))
            {
                user.Name = this.UserModel.Name;
                user.Surname = this.UserModel.Surname;
                user.Email = this.UserModel.Email;
                user.Surname = this.UserModel.Password;
                return user;
            }
            return null;
        }

        [HttpGet("GetValues")]
        [Authorize]
        public ActionResult<IEnumerable<string>> Get()
        {
            return Ok(new string[] { "value1", "value2", "value3" });
        }
    }
}
