using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Sofisoft.Accounts.Identity.API.Application.Adapters;
using Sofisoft.Accounts.Identity.API.Application.Services;
using Sofisoft.Accounts.Identity.API.Infrastructure.Exceptions;
using Sofisoft.Accounts.Identity.API.Models;
using Sofisoft.Accounts.Identity.API.ViewModels;

namespace Sofisoft.Accounts.Identity.API.Controllers
{
    [Route("api/v1/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly IUserService _userService;

        public UsersController(IUserService userService)
        {
            _userService = userService ?? throw new ArgumentNullException(nameof(userService));
        }

        #region Posts

        /// <summary>
        /// Crea un nuevo usuario.
        /// </summary>
        /// <param name="item">Objeto que se creara.</param>
        [Route("")]
        [HttpPost]
        [ProducesResponseType(typeof(User), StatusCodes.Status201Created)]
        [ProducesResponseType(typeof(ErrorViewModel), StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> Post([FromBody]UserRegisterDto item)
        {
            try
            {
                var result = await _userService.AddAsync(item);

                return CreatedAtAction("nameof(Get)", new { measureTypeId = result.Id}, result);
            }
            catch (IdentityDomainException ex)
            {
                return BadRequest(new ErrorViewModel(ex.ErrorId, ex.Message));
            }
        }

        #endregion
    }
}