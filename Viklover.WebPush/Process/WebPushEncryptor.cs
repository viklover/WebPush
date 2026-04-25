using System.Security.Cryptography;
using System.Text;

namespace Viklover.WebPush.Process;

public static class WebPushEncryptor {
    /// <summary>
    ///     Длина тэга в результирующем зашифрованном payload
    /// </summary>
    public const int TagLength = 16;
    /// <summary>
    ///     Объектное представление результата шифрования
    /// </summary>
    /// <param name="PublicKey">Публичный ключ</param>
    /// <param name="Payload">Зашифрованное содержимое уведомления</param>
    /// <param name="Salt">Соль</param>
    public record EncryptionResult(byte[] PublicKey, byte[] Payload, byte[] Salt);
    /// <summary>
    ///     Зашифровать уведомление используя реквизиты подписки
    /// </summary>
    /// <param name="userKey">Публичый ключ пользователя в base64</param>
    /// <param name="userSecret">Аутентификационный секрет в base64</param>
    /// <param name="payload">Содержимое уведомления</param>
    /// <returns>Результат шифрования</returns>
    public static EncryptionResult Encrypt(string userKey, string userSecret, string payload) {
        var userKeyBytes = WebPushHelper.DecodeBase64(userKey);
        var userSecretBytes = WebPushHelper.DecodeBase64(userSecret);
        var payloadBytes = Encoding.UTF8.GetBytes(payload);
        return Encrypt(userKeyBytes, userSecretBytes, payloadBytes);
    }
    /// <summary>
    ///     Зашифровать уведомление используя реквизиты подписки
    /// </summary>
    /// <param name="userKey">Публичый ключ пользователя</param>
    /// <param name="userSecret">Аутентификационный секрет</param>
    /// <param name="payload">Содержимое уведомления</param>
    /// <returns>Результат шифрования</returns>
    public static EncryptionResult Encrypt(byte[] userKey, byte[] userSecret, byte[] payload) {
        var salt = GenerateSalt(TagLength);
        var userKeyParams = CreateEcParameters(userKey, null);
        using var userKeyPair = ECDiffieHellman.Create(userKeyParams);
        using var serverKeyPair = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var key = serverKeyPair.DeriveRawSecretAgreement(userKeyPair.PublicKey);
        var serverPublicKeyParams = serverKeyPair.ExportParameters(true);
        var serverPublicKeyX = serverPublicKeyParams.Q.X!;
        var serverPublicKeyY = serverPublicKeyParams.Q.Y!;
        var serverPublicKey = new byte[1 + 32 + 32];
        serverPublicKey[0] = 0x04;
        Buffer.BlockCopy(serverPublicKeyX, 0, serverPublicKey, 1, serverPublicKeyX.Length);
        Buffer.BlockCopy(serverPublicKeyY, 0, serverPublicKey, serverPublicKeyX.Length + 1, serverPublicKeyY.Length);
        var prk = Hkdf(userSecret, key, "Content-Encoding: auth\0"u8.ToArray(), 32);
        var cek = Hkdf(salt, prk, CreateInfoChunk("aesgcm", userKey, serverPublicKey), TagLength);
        var nonce = Hkdf(salt, prk, CreateInfoChunk("nonce", userKey, serverPublicKey), 12);
        var payloadPadded = AddPaddingToInput(payload);
        var encryptedPayload = EncryptAes(nonce, cek, payloadPadded);
        return new EncryptionResult(serverPublicKey, encryptedPayload, salt);
    }
    /// <summary>
    ///     Расшифровать уведомление
    /// </summary>
    /// <param name="encryptedPayload">Зашифрованное сообщение</param>
    /// <param name="salt">Соль</param>
    /// <param name="serverPublicKey">Публичный ключ сервера</param>
    /// <param name="userPublicKey">Публичный ключ пользователя</param>
    /// <param name="userPrivateKey">Приватный ключ пользователя</param>
    /// <param name="userSecret">Аутентификационный секрет</param>
    /// <returns>Расшифрованное сообщение</returns>
    public static byte[] Decrypt(byte[] encryptedPayload, byte[] salt, byte[] serverPublicKey, byte[] userPublicKey, byte[] userPrivateKey, byte[] userSecret) {
        var serverKeyParams = CreateEcParameters(serverPublicKey, null);
        var userKeyParams = CreateEcParameters(userPublicKey, userPrivateKey);
        using var serverKeyPair = ECDiffieHellman.Create(serverKeyParams);
        using var userKeyPair = ECDiffieHellman.Create(userKeyParams);
        var key = userKeyPair.DeriveRawSecretAgreement(serverKeyPair.PublicKey);
        var prk = Hkdf(userSecret, key, "Content-Encoding: auth\0"u8.ToArray(), 32);
        var cek = Hkdf(salt, prk, CreateInfoChunk("aesgcm", userPublicKey, serverPublicKey), TagLength);
        var nonce = Hkdf(salt, prk, CreateInfoChunk("nonce", userPublicKey, serverPublicKey), 12);
        var payload = DecryptAes(nonce, cek, encryptedPayload);
        return RemovePaddingFromInput(payload);
    }
    /// <summary>
    ///     Сформировать <see cref="ECParameters"/> из указанных ключей
    /// </summary>
    /// <param name="publicKey">Публичный ключ</param>
    /// <param name="privateKey">Приватный ключ</param>
    /// <returns>Параметры эллиптических кривых</returns>
    public static ECParameters CreateEcParameters(byte[]? publicKey, byte[]? privateKey) {
        var parameters = new ECParameters { Curve = ECCurve.NamedCurves.nistP256 };
        if (publicKey != null) {
            var keyX = new byte[32];
            var keyY = new byte[32];
            Buffer.BlockCopy(publicKey, 1, keyX, 0, 32);
            Buffer.BlockCopy(publicKey, 33, keyY, 0, 32);
            parameters.Q.X = keyX;
            parameters.Q.Y = keyY;
        }
        if (privateKey != null) {
            parameters.D = privateKey;
        }
        return parameters;
    } 
    /// <summary>
    ///     Сгенерировать соль 
    /// </summary>
    /// <param name="length">Длина</param>
    /// <returns>Соль представленная массивом байтов</returns>
    public static byte[] GenerateSalt(int length) {
        var salt = new byte[length];
        Random.Shared.NextBytes(salt);
        return salt;
    }
    /// <summary>
    ///     Зашифровать сообщение с использованием AES алгоритма
    /// </summary>
    /// <param name="nonce">Уникальный вектор инициализации для шифрования</param>
    /// <param name="cek">Ключ шифрования (Content Encryption Key)</param>
    /// <param name="payload">Сообщение для шифрования</param>
    /// <returns>Зашифрованные данные</returns>
    public static byte[] EncryptAes(byte[] nonce, byte[] cek, byte[] payload) {
        using var aes = new AesGcm(cek, TagLength);
        var cipherMessage = new byte[payload.Length];
        var tag = new byte[TagLength];
        aes.Encrypt(nonce, payload, cipherMessage, tag);
        var result = new byte[cipherMessage.Length + tag.Length];
        Buffer.BlockCopy(cipherMessage, 0, result, 0, cipherMessage.Length);
        Buffer.BlockCopy(tag, 0, result, cipherMessage.Length, tag.Length);
        return result;
    }
    /// <summary>
    ///     Расшифровать сообщение с использованием AES алгоритма
    /// </summary>
    /// <param name="nonce">Уникальный вектор инициализации для шифрования</param>
    /// <param name="cek">Ключ шифрования (Content Encryption Key)</param>
    /// <param name="encryptedPayload">Зашифрованное сообщение</param>
    /// <returns>Зашифрованные данные</returns>
    public static byte[] DecryptAes(byte[] nonce, byte[] cek, byte[] encryptedPayload) {
        using var aes = new AesGcm(cek, TagLength);
        var cipherTextLength = encryptedPayload.Length - TagLength;
        var cipherMessage = new byte[cipherTextLength];
        var tag = new byte[TagLength];
        Buffer.BlockCopy(encryptedPayload, 0, cipherMessage, 0, cipherTextLength);
        Buffer.BlockCopy(encryptedPayload, cipherTextLength, tag, 0, TagLength);
        var decryptedMessage = new byte[cipherMessage.Length];
        aes.Decrypt(nonce, cipherMessage, tag, decryptedMessage);
        return decryptedMessage;
    }
    /// <summary>
    ///     Добавить выравнивание к входным данным для соответствия требованиям шифрования
    /// </summary>
    /// <param name="data">Входные данные для выравнивания</param>
    /// <returns>Данные с добавленным выравниванием</returns>
    public static byte[] AddPaddingToInput(byte[] data) {
        var input = new byte[0 + 2 + data.Length];
        Buffer.BlockCopy(ConvertInt(0), 0, input, 0, 2);
        Buffer.BlockCopy(data, 0, input, 0 + 2, data.Length);
        return input;
    }
    /// <summary>
    ///     Удалить выравнивание из входных данных
    /// </summary>
    /// <param name="data">Данные с добавленным выравниванием</param>
    /// <returns>Оригинальные данные без выравнивания</returns>
    public static byte[] RemovePaddingFromInput(byte[] data) { 
        var unpaddedDataLength = data.Length - 2;
        var originalData = new byte[unpaddedDataLength];
        Buffer.BlockCopy(data, 2, originalData, 0, unpaddedDataLength);
        return originalData;
    }
    /// <summary>
    ///     Выполнить второй шаг HKDF для генерации ключа.
    /// </summary>
    /// <param name="key">Исходный ключ для хешировани.</param>
    /// <param name="info">Дополнительная информация для хеширования</param>
    /// <param name="length">Длина результирующего ключа.</param>
    /// <returns>Сгенерированный ключ</returns>
    public static byte[] HkdfSecondStep(byte[] key, byte[] info, int length) {
        var infoAndOne = info.Concat(new byte[] { 0x01 }).ToArray();
        var result = ComputeHash(key, infoAndOne);
        if (result.Length > length) {
            Array.Resize(ref result, length);
        }
        return result;
    }
    /// <summary>
    ///     Выполнить процесс HKDF для извлечения ключа на основе соли и PRK.
    /// </summary>
    /// <param name="salt">Соль для процесса HKDF.</param>
    /// <param name="prk">Промежуточный ключ для извлечения.</param>
    /// <param name="info">Дополнительная информация для хеширования.</param>
    /// <param name="length">Длина результирующего ключа.</param>
    /// <returns>Сгенерированный ключ.</returns>
    public static byte[] Hkdf(byte[] salt, byte[] prk, byte[] info, int length) {
        var key = ComputeHash(salt, prk);
        return HkdfSecondStep(key, info, length);
    }
    /// <summary>
    ///     Преобразовать целое число в массив байтов в формате Big Endian.
    /// </summary>
    /// <param name="number">Целое число для преобразования.</param>
    /// <returns>Массив байтов, представляющий целое число.</returns>
    public static byte[] ConvertInt(int number) {
        var output = BitConverter.GetBytes(Convert.ToUInt16(number));
        if (BitConverter.IsLittleEndian) {
            Array.Reverse(output);
        }
        return output;
    }
    /// <summary>
    ///     Создать информационный фрагмент для передачи ключей.
    /// </summary>
    /// <param name="type">Тип контента для кодирования.</param>
    /// <param name="recipientPublicKey">Публичный ключ получателя.</param>
    /// <param name="senderPublicKey">Публичный ключ отправителя.</param>
    /// <returns>Массив байтов, содержащий информационный фрагмент.</returns>
    public static byte[] CreateInfoChunk(string type, byte[] recipientPublicKey, byte[] senderPublicKey) {
        var output = new List<byte>();
        output.AddRange(Encoding.UTF8.GetBytes($"Content-Encoding: {type}\0P-256\0"));
        output.AddRange(ConvertInt(recipientPublicKey.Length));
        output.AddRange(recipientPublicKey);
        output.AddRange(ConvertInt(senderPublicKey.Length));
        output.AddRange(senderPublicKey);
        return output.ToArray();
    }
    /// <summary>
    ///     Вычислить HMAC хэш на основе заданного ключа и значения.
    /// </summary>
    /// <param name="key">Ключ для вычисления хэша.</param>
    /// <param name="value">Значение для хеширования.</param>
    /// <returns>Результирующий HMAC хэш</returns>
    public static byte[] ComputeHash(byte[] key, byte[] value) {
        using var hasher = new HMACSHA256(key);
        return hasher.ComputeHash(value);
    }
}
