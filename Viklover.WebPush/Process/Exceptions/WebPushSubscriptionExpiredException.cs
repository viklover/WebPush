using Viklover.WebPush.Model;

namespace Viklover.WebPush.Process.Exceptions;
/// <summary>
///     Exception thrown when a subscription has expired
/// </summary>
/// <param name="subscription">Expired subscription</param>
public class WebPushSubscriptionExpiredException(WebPushSubscription subscription) : WebPushException("Subscription is expired") {
    /// <summary>
	/// 	Expired subscription
	/// </summary>
	public WebPushSubscription Subscription { get; } = subscription;
}
