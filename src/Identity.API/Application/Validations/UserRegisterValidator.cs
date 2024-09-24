using System.Collections.Generic;
using System.Linq;
using FluentValidation;
using Sofisoft.Accounts.Identity.API.Application.Adapters;

namespace Sofisoft.Accounts.Identity.API.Application.Validations
{
    public class UserRegisterValidator : AbstractValidator<UserRegisterDto>
    {
        public UserRegisterValidator()
        {
            RuleFor(x => x.Alias).Length(3, 30).NotEmpty();
            RuleFor(x => x.UserName).Length(3, 30).NotEmpty();
            RuleFor(x => x.Password)
                .Length(8, 20)
                .NotEmpty()
                .WithMessage("La contraseña debe tener entre 8 y 20 caracteres.");
            RuleFor(x => x.Password)
                .Must(PasswordRequiresLower)
                .WithMessage("La contraseña debe tener al menos una minúscula ('a' - 'z').");
            RuleFor(x => x.Password)
                .Must(PasswordRequiresUpper)
                .WithMessage("La contraseña debe tener al menos una mayúscula ('A' - 'Z').");
            RuleFor(x => x.Password)
                .Must(PasswordRequiresDigit)
                .WithMessage("La contraseña debe tener al menos un dígito ('0' - '9').");
            RuleFor(x => x.Password)
                .Must(PasswordRequiresNonAlphanumeric)
                .WithMessage("La contraseña debe tener al menos un carácter no alfanumérico.");
        }

        private bool PasswordRequiresDigit(string password) => (password ?? string.Empty).Any(char.IsDigit);
        private bool PasswordRequiresLower(string password) => (password ?? string.Empty).Any(char.IsLower);
        private bool PasswordRequiresNonAlphanumeric(string password)
        {
            HashSet<char> specialCharacters = new HashSet<char>() { '%', '$', '#' };
            
            return (password ?? string.Empty).Any(specialCharacters.Contains);
        }
        private bool PasswordRequiresUpper(string password) => (password ?? string.Empty).Any(char.IsUpper);


    }
}