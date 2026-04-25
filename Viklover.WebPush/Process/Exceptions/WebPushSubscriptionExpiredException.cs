using Viklover.WebPush.Model;

namespace Viklover.WebPush.Process.Exceptions;
/// <summary>
///     Исключение выброшенное по причине истечения срока подписки
/// </summary>
/// <param name="subscription">Истёкшая подписка</param>
public class WebPushSubscriptionExpiredException(WebPushSubscription subscription) : WebPushException("Subscription is expired") {
    /// <summary>
	/// 	Истёкшая подписка
	/// </summary>
	public WebPushSubscription Subscription { get; } = subscription;
}
