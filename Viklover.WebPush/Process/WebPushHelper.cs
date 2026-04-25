using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Viklover.WebPush.Process;
/// <summary>
///     Helper methods for Web Push operations
/// </summary>
public static class WebPushHelper {
    /// <summary>
    ///     Build a JWT token
    /// </summary>
    /// <param name="endpoint">Endpoint for sending notification</param>
    /// <param name="privateKey">Server private key encoded in base64</param>
    /// <returns>Generated JWT token</returns>
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
    ///     Build a JWT message
    /// </summary>
    /// <param name="header">Header</param>
    /// <param name="payload">Payload</param>
    /// <param name="privateKey">Secret key</param>
    /// <returns>Built message</returns>
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
    ///     Serialize to Base64-encoded JSON
    /// </summary>
    /// <param name="data">Data to serialize</param>
    /// <returns>Resulting string</returns>
    public static string SerializeToBase64EncodedJson(IReadOnlyDictionary<string, object> data) {
        var jsonString = JsonSerializer.Serialize(data);
        var binaryString = Encoding.UTF8.GetBytes(jsonString);
        var base64String = EncodeBase64(binaryString);
        return base64String;
    }
    /// <summary>
    ///     Convert url base64 to byte array
    /// </summary>
    /// <param name="input">Base64</param>
    /// <returns>Deserialized byte array</returns>
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
    ///     Convert byte array to url base64
    /// </summary>
    /// <param name="input">Byte array</param>
    /// <returns>Base64</returns>
    public static string EncodeBase64(byte[] input) {
        try {
            return Convert.ToBase64String(input).Replace('+', '-').Replace('/', '_').TrimEnd('=');
        } catch (Exception exception) {
            throw new WebPushException("Failed to resolve base64 from string content", exception);
        }
    }
}
