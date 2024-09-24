using System;

namespace Sofisoft.Accounts.Identity.API.Utils
{
    public static class Helper
    {

        public static string GenerateSecurityStamp()
        {
            var guid = Guid.NewGuid();

			return String.Concat(
                Array.ConvertAll(guid.ToByteArray(), b => b.ToString("X2")));
        }
    }
}