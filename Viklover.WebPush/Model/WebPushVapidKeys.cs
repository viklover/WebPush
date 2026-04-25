namespace Viklover.WebPush.Model;
/// <summary>
///     Объектное представление ключей vapid
/// </summary>
/// <param name="PublicKey">Публичный ключ</param>
/// <param name="PrivateKey">Приватный ключ</param>
public record WebPushVapidKeys(string PublicKey, string PrivateKey);