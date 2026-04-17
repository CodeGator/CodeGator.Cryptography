
namespace CodeGator.Cryptography;

/// <summary>
/// This class contains unit tests for <see cref="CryptoServiceExtensions"/>.
/// </summary>
[TestClass]
public sealed class CryptoServiceExtensionsTests
{
    /// <summary>
    /// This method creates a service and key material for extension tests.
    /// </summary>
    /// <returns>The service and a derived <see cref="KeyAndIV"/>.</returns>
    private static (ICryptoService Service, KeyAndIV KeyAndIV) CreateServiceWithKey()
    {
        var logger = new Mock<ILogger<CryptoService>>();
        var service = new CryptoService(
            RandomNumberGenerator.Create(),
            logger.Object
            );

        var keyAndIV = service.GenerateKeyAndIVAsync("extension-test", "salt", "SHA512").GetAwaiter().GetResult();
        return (service, keyAndIV);
    }

    /// <summary>
    /// This method verifies byte-array extension overloads round-trip correctly.
    /// </summary>
    /// <returns>A task that represents the asynchronous test operation.</returns>
    [TestCategory("Unit")]
    [TestMethod]
    public async Task Extension_ByteArray_EncryptDecrypt_RoundTrips()
    {
        var (service, keyAndIV) = CreateServiceWithKey();
        var original = RandomNumberGenerator.GetBytes(200);

        var cipher = await service.AesEncryptAsync(
            keyAndIV.Key,
            keyAndIV.IV,
            original
            );

        var plain = await service.AesDecryptAsync(
            keyAndIV.Key,
            keyAndIV.IV,
            cipher
            );

        CollectionAssert.AreEqual(original, plain);
    }

    /// <summary>
    /// This method verifies string extension overloads round-trip correctly.
    /// </summary>
    /// <returns>A task that represents the asynchronous test operation.</returns>
    [TestCategory("Unit")]
    [TestMethod]
    public async Task Extension_String_EncryptDecrypt_RoundTrips()
    {
        var (service, keyAndIV) = CreateServiceWithKey();
        var original = "Plain text with unicode: ñ 🎉";

        var cipher = await service.AesEncryptAsync(
            keyAndIV.Key,
            keyAndIV.IV,
            original
            );

        var plain = await service.AesDecryptAsync(
            keyAndIV.Key,
            keyAndIV.IV,
            cipher
            );

        Assert.AreEqual(original, plain);
    }

    /// <summary>
    /// This method verifies stream extension overloads round-trip correctly.
    /// </summary>
    /// <returns>A task that represents the asynchronous test operation.</returns>
    [TestCategory("Unit")]
    [TestMethod]
    public async Task Extension_Stream_EncryptDecrypt_RoundTrips()
    {
        var (service, keyAndIV) = CreateServiceWithKey();

        using var originalStream = new MemoryStream(RandomNumberGenerator.GetBytes(256));
        using var cipherStream = new MemoryStream();
        using var plainStream = new MemoryStream();

        await service.AesEncryptAsync(
            keyAndIV.Key,
            keyAndIV.IV,
            originalStream,
            cipherStream
            );

        originalStream.Position = 0;
        cipherStream.Position = 0;

        await service.AesDecryptAsync(
            keyAndIV.Key,
            keyAndIV.IV,
            cipherStream,
            plainStream
            );

        Assert.AreEqual(originalStream.Length, plainStream.Length);
        CollectionAssert.AreEqual(originalStream.ToArray(), plainStream.ToArray());
    }

    /// <summary>
    /// This method verifies a null service throws <see cref="ArgumentNullException"/>.
    /// </summary>
    /// <returns>A task that represents the asynchronous test operation.</returns>
    [TestCategory("Unit")]
    [TestMethod]
    public async Task Extension_NullService_ThrowsArgumentNullException()
    {
        ICryptoService? service = null;
        var key = new byte[32];
        var iv = new byte[16];

        await Assert.ThrowsExactlyAsync<ArgumentNullException>(
            () => service!.AesEncryptAsync(key, iv, new byte[] { 1 })
            );
    }
}
