using MongoDB.Bson.Serialization.Attributes;
using Sofisoft.Enterprise.SeedWork.MongoDB.Attributes;
using Sofisoft.Enterprise.SeedWork.MongoDB.Domain;

namespace Sofisoft.Accounts.Identity.API.Models
{
    [BsonCollection("clientApp")]
    public class ClientApp : Document
    {
        /// <summary>
        /// Get or set the name of the client app.
        /// </summary>
        [BsonElement("name")]
        public string Name { get; set; }

        /// <summary>
        /// Get or set the redirectUri.
        /// </summary>
        [BsonElement("redirectUri")]
        public string RedirectUri { get; set; }

        /// <summary>
        /// True if it is a third-party client application, otherwise false.
        /// </summary>
        [BsonElement("thirdParty")]
        public bool ThirdParty { get; set; }

        /// <summary>
        /// True if the client app is active, otherwise false.
        /// </summary>
        [BsonElement("active")]
        public bool Active { get; set; }
    }
}