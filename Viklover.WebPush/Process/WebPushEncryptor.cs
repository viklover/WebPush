using System.Security.Cryptography;
using System.Text;

namespace Viklover.WebPush.Process;

public static class WebPushEncryptor {
    /// <summary>
    ///     Tag length in resulting encrypted payload
    /// </summary>
    public const int TagLength = 16;
    /// <summary>
    ///     Object representation of encryption result
    /// </summary>
    /// <param name="PublicKey">Public key</param>
    /// <param name="Payload">Encrypted notification content</param>
    /// <param name="Salt">Salt</param>
    public record EncryptionResult(byte[] PublicKey, byte[] Payload, byte[] Salt);
    /// <summary>
    ///     Encrypt notification using subscription details
    /// </summary>
    /// <param name="userKey">User public key in base64</param>
    /// <param name="userSecret">Authentication secret in base64</param>
    /// <param name="payload">Notification content</param>
    /// <returns>Encryption result</returns>
    public static EncryptionResult Encrypt(string userKey, string userSecret, string payload) {
        var userKeyBytes = WebPushHelper.DecodeBase64(userKey);
        var userSecretBytes = WebPushHelper.DecodeBase64(userSecret);
        var payloadBytes = Encoding.UTF8.GetBytes(payload);
        return Encrypt(userKeyBytes, userSecretBytes, payloadBytes);
    }
    /// <summary>
    ///     Encrypt notification using subscription details
    /// </summary>
    /// <param name="userKey">User public key</param>
    /// <param name="userSecret">Authentication secret</param>
    /// <param name="payload">Notification content</param>
    /// <returns>Encryption result</returns>
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
    ///     Decrypt notification
    /// </summary>
    /// <param name="encryptedPayload">Encrypted message</param>
    /// <param name="salt">Salt</param>
    /// <param name="serverPublicKey">Server public key</param>
    /// <param name="userPublicKey">User public key</param>
    /// <param name="userPrivateKey">User private key</param>
    /// <param name="userSecret">Authentication secret</param>
    /// <returns>Decrypted message</returns>
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
    ///     Build <see cref="ECParameters"/> from the specified keys
    /// </summary>
    /// <param name="publicKey">Public key</param>
    /// <param name="privateKey">Private key</param>
    /// <returns>Elliptic curve parameters</returns>
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
    ///     Generate salt
    /// </summary>
    /// <param name="length">Length</param>
    /// <returns>Salt as byte array</returns>
    public static byte[] GenerateSalt(int length) {
        var salt = new byte[length];
        Random.Shared.NextBytes(salt);
        return salt;
    }
    /// <summary>
    ///     Encrypt message using AES algorithm
    /// </summary>
    /// <param name="nonce">Unique initialization vector for encryption</param>
    /// <param name="cek">Content Encryption Key</param>
    /// <param name="payload">Message to encrypt</param>
    /// <returns>Encrypted data</returns>
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
    ///     Decrypt message using AES algorithm
    /// </summary>
    /// <param name="nonce">Unique initialization vector for encryption</param>
    /// <param name="cek">Content Encryption Key</param>
    /// <param name="encryptedPayload">Encrypted message</param>
    /// <returns>Decrypted data</returns>
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
    ///     Add padding to input data for encryption requirements
    /// </summary>
    /// <param name="data">Input data to pad</param>
    /// <returns>Data with added padding</returns>
    public static byte[] AddPaddingToInput(byte[] data) {
        var input = new byte[0 + 2 + data.Length];
        Buffer.BlockCopy(ConvertInt(0), 0, input, 0, 2);
        Buffer.BlockCopy(data, 0, input, 0 + 2, data.Length);
        return input;
    }
    /// <summary>
    ///     Remove padding from input data
    /// </summary>
    /// <param name="data">Data with padding</param>
    /// <returns>Original data without padding</returns>
    public static byte[] RemovePaddingFromInput(byte[] data) { 
        var unpaddedDataLength = data.Length - 2;
        var originalData = new byte[unpaddedDataLength];
        Buffer.BlockCopy(data, 2, originalData, 0, unpaddedDataLength);
        return originalData;
    }
    /// <summary>
    ///     Perform the second step of HKDF for key generation.
    /// </summary>
    /// <param name="key">Source key for hashing.</param>
    /// <param name="info">Additional info for hashing</param>
    /// <param name="length">Resulting key length.</param>
    /// <returns>Generated key</returns>
    public static byte[] HkdfSecondStep(byte[] key, byte[] info, int length) {
        var infoAndOne = info.Concat(new byte[] { 0x01 }).ToArray();
        var result = ComputeHash(key, infoAndOne);
        if (result.Length > length) {
            Array.Resize(ref result, length);
        }
        return result;
    }
    /// <summary>
    ///     Perform HKDF process for key derivation using salt and PRK.
    /// </summary>
    /// <param name="salt">Salt for HKDF process.</param>
    /// <param name="prk">Pseudorandom key for derivation.</param>
    /// <param name="info">Additional info for hashing.</param>
    /// <param name="length">Resulting key length.</param>
    /// <returns>Generated key.</returns>
    public static byte[] Hkdf(byte[] salt, byte[] prk, byte[] info, int length) {
        var key = ComputeHash(salt, prk);
        return HkdfSecondStep(key, info, length);
    }
    /// <summary>
    ///     Convert integer to byte array in Big Endian format.
    /// </summary>
    /// <param name="number">Integer to convert.</param>
    /// <returns>Byte array representing the integer.</returns>
    public static byte[] ConvertInt(int number) {
        var output = BitConverter.GetBytes(Convert.ToUInt16(number));
        if (BitConverter.IsLittleEndian) {
            Array.Reverse(output);
        }
        return output;
    }
    /// <summary>
    ///     Create an info chunk for key derivation.
    /// </summary>
    /// <param name="type">Content type to encode.</param>
    /// <param name="recipientPublicKey">Recipient public key.</param>
    /// <param name="senderPublicKey">Sender public key.</param>
    /// <returns>Byte array containing the info chunk.</returns>
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
    ///     Compute HMAC hash based on the given key and value.
    /// </summary>
    /// <param name="key">Key for hash computation.</param>
    /// <param name="value">Value to hash.</param>
    /// <returns>Resulting HMAC hash</returns>
    public static byte[] ComputeHash(byte[] key, byte[] value) {
        using var hasher = new HMACSHA256(key);
        return hasher.ComputeHash(value);
    }
}
