namespace Viklover.WebPush.Model;
/// <summary>
/// 	Объектное представление подписки на PUSH-уведомления
/// </summary>
/// <param name="Endpoint">Эндпоинт к пуш-сервису браузера пользователя</param>
/// <param name="Auth">Аутентификационный секрет</param>
/// <param name="P256dh">Публичный ключ</param>
public record WebPushSubscription(string Endpoint, string Auth, string P256dh);
