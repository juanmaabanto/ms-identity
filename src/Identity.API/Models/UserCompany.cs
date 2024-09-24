using System;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Sofisoft.Accounts.Identity.API.Models
{
    public class UserCompany
    {
        [BsonRepresentation(BsonType.ObjectId)]
        [BsonElement("companyId")]
        public string CompanyId { get; set; }

        [BsonElement("principal")]
        public bool Principal { get; set; }
    }
}