namespace Viklover.WebPush;
/// <summary>
///     Base exception
/// </summary>
public class WebPushException : Exception {
    /// <summary>
    ///     Constructor of exception
    /// </summary>
    /// <param name="message">Message</param>
    public WebPushException(string message) : base(message) {}
    /// <summary>
    ///     Constructor of exception
    /// </summary>
    /// <param name="message">Message</param>
    /// <param name="innerException">Inner exception</param>
    public WebPushException(string message, Exception innerException) : base(message, innerException) {}
}
