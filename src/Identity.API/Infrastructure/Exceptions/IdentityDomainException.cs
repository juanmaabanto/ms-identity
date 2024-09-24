using System;

namespace Sofisoft.Accounts.Identity.API.Infrastructure.Exceptions
{
    public class IdentityDomainException : Exception
    {
        private string errorId;

        public string ErrorId => errorId;

        public IdentityDomainException()
        { }

        public IdentityDomainException(string message)
            : base(message)
        { }

        public IdentityDomainException(string message, string errorId)
            : base(message)
        { 
            this.errorId = errorId;
        }
    }
}