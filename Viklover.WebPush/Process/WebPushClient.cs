using System.Net;
using System.Net.Http.Headers;
using Viklover.WebPush.Model;
using Viklover.WebPush.Process.Exceptions;

namespace Viklover.WebPush.Process;
/// <summary>
///     Клиент к пуш-сервисам
/// </summary>
/// <param name="vapid">VAPID ключи</param>
/// <param name="notificationTTL">Длительность жизни уведомления</param>
public class WebPushClient(WebPushVapidKeys vapid, TimeSpan notificationTTL) {
	private readonly HttpClient _client = new();
    /// <summary>
    ///     Конструктор клиента к пуш-сервисам
    /// </summary>
    /// <param name="httpClient"><see cref="HttpClient"/></param>
    /// <param name="vapid">VAPID ключи</param>
    /// <param name="notificationTTL">Длительность жизни уведомления</param>
    public WebPushClient(HttpClient httpClient, WebPushVapidKeys vapid, TimeSpan notificationTTL) : this(vapid, notificationTTL) {
        _client = httpClient;
    }
    /// <summary>
    ///     Отправить уведомление по подписке в асинхронной манере
    /// </summary>
    /// <param name="subscription">Подписка</param>
    /// <param name="payload">Уведомление</param>
    /// <param name="cancellationToken">Токен отмены асинхронной операции</param>
    /// <returns>Асинхронная задача на отправку уведомления</returns>
    public async Task SendAsync(WebPushSubscription subscription, string payload, CancellationToken cancellationToken) {
        try {
            using var request = CreateRequest(subscription, vapid, payload, notificationTTL);
            using var response = await _client.SendAsync(request, cancellationToken);
            if (response.StatusCode == HttpStatusCode.Gone) {
                throw new WebPushSubscriptionExpiredException(subscription);
            }
            if (response.StatusCode == HttpStatusCode.OK) {
                return;
            }
            if (response.StatusCode == HttpStatusCode.Created) {
                return;
            }
            var r = await response.Content.ReadAsStringAsync(cancellationToken);
            throw new WebPushException($"Unexpected response status code: {response.StatusCode}: {r}");
        } catch (WebPushSubscriptionExpiredException) {
            throw;
        } catch (Exception exception) {
            throw new WebPushException("Failed to send notification to push service", exception);
        }
    }
    /// <summary>
	/// 	Разрешение запроса на отправку уведомления
	/// </summary>
	/// <param name="subscription">Подписка</param>
	/// <param name="vapid">Ключи vapid</param>
	/// <param name="payload">Содержимое сообщения</param>
	/// <param name="ttl">Длительность жизни уведомления</param>
	/// <returns>Подготовленный запрос на отправку уведомления</returns>
    public static HttpRequestMessage CreateRequest(WebPushSubscription subscription, WebPushVapidKeys vapid, string payload, TimeSpan ttl) {
        var jwt = WebPushHelper.BuildJwt(subscription.Endpoint, vapid.PrivateKey);
        var encryptedPayload = WebPushEncryptor.Encrypt(subscription.P256dh, subscription.Auth, payload);
        var request = new HttpRequestMessage(HttpMethod.Post, subscription.Endpoint) {
            Content = new ByteArrayContent(encryptedPayload.Payload)
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        request.Content.Headers.ContentLength = encryptedPayload.Payload.Length;
        request.Content.Headers.ContentEncoding.Add("aesgcm");
        request.Headers.Add("Encryption", $"salt={WebPushHelper.EncodeBase64(encryptedPayload.Salt)}");
        var cryptoKeyHeader = $"dh={WebPushHelper.EncodeBase64(encryptedPayload.PublicKey)};p256ecdsa={vapid.PublicKey}";
        request.Headers.Add("TTL", ttl.Seconds.ToString());
        request.Headers.Add("Crypto-Key", cryptoKeyHeader);
        request.Headers.Add("Authorization", $"WebPush {jwt}");
        return request;
    }
}
