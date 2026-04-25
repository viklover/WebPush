using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Viklover.WebPush.Process;
/// <summary>
///     
/// </summary>
public static class WebPushHelper {
    /// <summary>
    ///     Сформировать JWT токен
    /// </summary>
    /// <param name="endpoint">Конечная точка на отправку уведомления</param>
    /// <param name="privateKey">Приватный ключ сервера закодированный в base64</param>
    /// <returns>Сформированный jwt-токен</returns>
    public static string BuildJwt(string endpoint, string privateKey) {
        const int hourInSeconds = 60 * 60;
        var audienceUri = new Uri(endpoint);
        var audience = audienceUri.Scheme + @"://" + audienceUri.Host;
        var unixTimestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var expiration = unixTimestamp + hourInSeconds * 12;
        var header = new Dictionary<string, object> {
            {"typ", "JWT"},
            {"alg", "ES256"}
        };
        var payload = new Dictionary<string, object> {
            {"aud", audience},
            {"exp", expiration},
            {"sub", endpoint}
        };
        var result = BuildJwt(header, payload, privateKey);
        return result;
    }
    /// <summary>
    ///     Сборка сообщения JWT
    /// </summary>
    /// <param name="header">Заголовок</param>
    /// <param name="payload">Полезная нагрузка</param>
    /// <param name="privateKey">Секретный ключ</param>
    /// <returns>Собранное сообщение</returns>
    public static string BuildJwt(IReadOnlyDictionary<string, object> header, IReadOnlyDictionary<string, object> payload, string privateKey) {
        var encodedHeader = SerializeToBase64EncodedJson(header);
        var encodedPayload = SerializeToBase64EncodedJson(payload);
        var encodedData = $"{encodedHeader}.{encodedPayload}";
        var message = Encoding.UTF8.GetBytes(encodedData);
        using var signer = ECDsa.Create(new ECParameters {
            Curve = ECCurve.NamedCurves.nistP256,
            D = DecodeBase64(privateKey)
        });
        var signature = signer.SignData(message, HashAlgorithmName.SHA256);
        var encodedSignature = EncodeBase64(signature);
        var result = $"{encodedData}.{encodedSignature}";
        return result;
    }
    /// <summary>
    ///     Преобразовать в закодированный в BASE64 JSON
    /// </summary>
    /// <param name="data">Данные для преобразования</param>
    /// <returns>Результирующая строка</returns>
    public static string SerializeToBase64EncodedJson(IReadOnlyDictionary<string, object> data) {
        var jsonString = JsonSerializer.Serialize(data);
        var binaryString = Encoding.UTF8.GetBytes(jsonString);
        var base64String = EncodeBase64(binaryString);
        return base64String;
    }
    /// <summary>
    ///     Конвертировать url base64 в массив байтов
    /// </summary>
    /// <param name="input">Base64</param>
    /// <returns>Десериализованный массив байтов</returns>
    public static byte[] DecodeBase64(string input) {
        try {
            input = input.Replace('-', '+').Replace('_', '/');
            while (input.Length % 4 != 0) {
                input += "=";
            }
            return Convert.FromBase64String(input);
        } catch (Exception exception) {
            throw new WebPushException("Failed to resolve content from UrlBase64 content", exception);
        }
    }
    /// <summary>
    ///     Привести массив байтов к url base64
    /// </summary>
    /// <param name="input">Массив байтов</param>
    /// <returns>Base64</returns>
    public static string EncodeBase64(byte[] input) {
        try {
            return Convert.ToBase64String(input).Replace('+', '-').Replace('/', '_').TrimEnd('=');
        } catch (Exception exception) {
            throw new WebPushException("Failed to resolve base64 from string content", exception);
        }
    }
}
