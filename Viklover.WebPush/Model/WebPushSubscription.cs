namespace Viklover.WebPush.Model;
/// <summary>
///     Push notification subscription
/// </summary>
/// <param name="Endpoint">Endpoint to the user's browser push service</param>
/// <param name="Auth">Authentication secret</param>
/// <param name="P256dh">Public key</param>
public record WebPushSubscription(string Endpoint, string Auth, string P256dh);
