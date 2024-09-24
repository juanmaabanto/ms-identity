
using System;
using System.Collections.Generic;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using Sofisoft.Enterprise.SeedWork.MongoDB.Attributes;
using Sofisoft.Enterprise.SeedWork.MongoDB.Domain;

namespace Sofisoft.Accounts.Identity.API.Models
{
    [BsonCollection("user")]
    public class User : Document
    {
        /// <summary>
        /// Get or set the workspace Id.
        /// </summary>
        [BsonRepresentation(BsonType.ObjectId)]
        [BsonElement("workspaceId")]
        public string WorkspaceId { get; set; }

        /// <summary>
        /// Get or set the user name.
        /// </summary>
        [BsonElement("userName")]
        public string UserName { get; set; }

        /// <summary>
        /// Get or set the user's password.
        /// </summary>
        [BsonElement("passwordHash")]
        public string PasswordHash { get; set; }

        /// <summary>
        /// Get or set the normalized user name.
        /// </summary>
        [BsonElement("normalizedUserName")]
        public string NormalizedUserName { get; set; }

        /// <summary>
        /// Get or set the user's alias.
        /// </summary>
        [BsonElement("alias")]
        public string Alias { get; set; }

        /// <summary>
        /// Get or set the uri's image
        /// </summary>
        [BsonIgnoreIfNull]
        [BsonElement("imageUri")]
        public string ImageUri { get; set; }

        /// <summary>
        /// Get or set account failed login attempts
        /// </summary>
        [BsonElement("accessFailedCount")]
        public int AccessFailedCount { get; set; }

        /// <summary>
        /// True if the user can be blocked, otherwise false.
        /// </summary>
        [BsonElement("lockoutEnabled")]
        public bool LockoutEnabled { get; set; }

        /// <summary>
        /// Get or set the date and time for the end of the lock.
        /// </summary>
        [BsonIgnoreIfNull]
        [BsonRepresentation(BsonType.DateTime)]
        [BsonElement("lockoutEnd")]
        public DateTime? LockoutEnd { get; set; }

        /// <summary>
        /// True if the user's password expires, otherwise false.
        /// </summary>
        [BsonElement("passwordExpiresEnabled")]
        public bool PasswordExpiresEnabled { get; set; }

        /// <summary>
        /// Get or set the password expiration date.
        /// </summary>
        [BsonElement("passwordExpires")]
        public DateTime? PasswordExpires { get; set; }

        /// <summary>
        /// True if the user is required to change the password, otherwise false.
        /// </summary>
        [BsonElement("requestPasswordChange")]
        public bool RequestPasswordChange { get; set; }

        /// <summary>
        /// A random value that should change whenever a users credentials have changed.
        /// </summary>
        [BsonElement("securityStamp")]
        public string SecurityStamp { get; set; }

        /// <summary>
        /// True if the user is active, otherwise false.
        /// </summary>
        [BsonElement("active")]
        public bool Active { get; set; }

        /// <summary>
        /// Get or set to list of the user's client app.
        /// </summary>
        [BsonElement("clientApps")]
        public List<UserClientApp> ClientApps { get; set; }

        /// <summary>
        /// Get or set to list of the user's companies.
        /// </summary>
        [BsonElement("companies")]
        public List<UserCompany> Companies { get; set; }

        #region Methods

        public bool IsLockedOut()
        {
            if(!LockoutEnabled || LockoutEnd is null)
            {
                return false;
            }

            return DateTime.Compare(DateTime.UtcNow, LockoutEnd.Value) <= 0;
        }

        #endregion
        
    }
}