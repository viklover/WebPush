namespace Viklover.WebPush.Model;
/// <summary>
///     VAPID keys
/// </summary>
/// <param name="PublicKey">Public key</param>
/// <param name="PrivateKey">Private key</param>
public record WebPushVapidKeys(string PublicKey, string PrivateKey);