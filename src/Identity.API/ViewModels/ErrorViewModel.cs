namespace Sofisoft.Accounts.Identity.API.ViewModels
{
    /// <summary>
    /// Error model returned to user.
    /// </summary>
    public class ErrorViewModel
    {
        /// <summary>
        /// Gets the id of the event record.
        /// </summary>
        public string Id { get; }

        /// <summary>
        /// Get the error message.
        /// </summary>
        /// <value></value>
        public string Message { get; }

        /// <summary>
        /// Create a new error model to display to the user.
        /// </summary>
        /// <param name="id">Record id.</param>
        /// <param name="message">Message to display.</param>
        public ErrorViewModel(string id, string message)
        {
            Id = id;
            Message = message;
        }

        /// <summary>
        /// Create a new error model to display to the user.
        /// </summary>
        /// <param name="message">Message to display.</param>
        public ErrorViewModel(string message)
        {
            Message = message;
        }
    }
}