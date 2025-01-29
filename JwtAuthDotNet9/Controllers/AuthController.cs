using JwtAuthDotNet9.Data;
using JwtAuthDotNet9.Entities;
using JwtAuthDotNet9.Models;
using JwtAuthDotNet9.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Mail;
using System.Security.Claims;
using System.Text;

namespace JwtAuthDotNet9.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IAuthService authService, AppDbContext context) : ControllerBase
    {
        public static User user = new();

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            var result = await authService.RegisterAsync(request);
            if(result is null)
            {
                return BadRequest("Username already exists.");
            }

            return Ok(result);
        }

        [HttpPost("login")]
        public async Task<ActionResult<TokenResponseDto>> Login(UserDto request)
        {
            var token = await authService.LoginAsync(request);
            if(token is null)
            {
                return BadRequest("Invalid username or password.");
            }

            return Ok(token);
        }

        [HttpPost("refresh-token")]
        public async Task<ActionResult<TokenResponseDto>> RefreshToken(RefreshTokenRequestDto request)
        {
            var result = await authService.RefreshTokenAsync(request);
            if (result is null || result.AccessToken is null || result.RefreshToken is null)
                return Unauthorized("Invalid refresh token.");

            return Ok(result);
        }

        [Authorize]
        [HttpGet]
        public IActionResult AuthenticatedOnlyEndpoint()
        {
            
            return Ok("You are authenticated!");
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("admin")]
        public IActionResult AdminOnlyEndpoint()
        {

            return Ok("You are and admin!");
        }

        [HttpGet("user")]
        public async Task<IActionResult> Get()
        {
            var getUser = await context.Users.ToListAsync();
            return Ok(getUser);
        }

    }
}
