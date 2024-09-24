using System;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Sofisoft.Accounts.Identity.API.Models
{
    public class UserClientApp
    {
        [BsonRepresentation(BsonType.ObjectId)]
        [BsonElement("clientAppId")]
        public string ClientAppId { get; set; }
        
        [BsonElement("createdAt")]
        [BsonRepresentation(BsonType.DateTime)]
        public DateTime CreatedAt { get; set; }

        [BsonElement("permitted")]
        public bool Permitted { get; set; }

        [BsonElement("hasAccess")]
        public bool HasAccess { get; set; }
    }
}