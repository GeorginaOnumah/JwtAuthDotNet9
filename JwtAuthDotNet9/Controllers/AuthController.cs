using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JwtAuthDotNet9.Entities;
using JwtAuthDotNet9.Models;
using JwtAuthDotNet9.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JwtAuthDotNet9.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController (IAuthService authservice): ControllerBase
    {
        [HttpPost("register")]
        public async Task<ActionResult<User>> Register (UserDto request)
        {
            var user = await authservice.RegisterAsync(request);
            if (user is null)
                return BadRequest("User Already Exists.");
            
            return Ok(user);
        }

        [HttpPost ("login")]
        public async Task<ActionResult<TokenResponseDto>> Login(UserDto request) 
        {
           var results = await authservice.LoginAsync(request);
            if (results is null)
                return BadRequest("Invalid Credentials.");

            return Ok(results);
        }

        [HttpPost("refresh-token")]
        public async Task<ActionResult<TokenResponseDto>> RefreshToken(RefreshTokenRequestDto request)
        {
            var result = await authservice.RefreshTokensAsync(request);
            if (result is null || result.AccessToken is null || result.RefreshToken is null)
                return Unauthorized("Invalid Refresh Token.");
            return Ok(result);
        }

        [Authorize]
        [HttpGet]
        public IActionResult AuthenticatedOnlyEndpoint() 
        {
            return Ok("You are authenticated!");
        }

        [Authorize (Roles = "Admin")]
        [HttpGet ("admin-only")]
        public IActionResult AdminOnlyEndpoint()
        {
            return Ok("You are an admin!");
        }
    }
}
