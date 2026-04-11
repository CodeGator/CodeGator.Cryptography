
namespace CodeGator.Cryptography;

/// <summary>
/// Unit tests for <see cref="CryptoServiceExtensions"/>.
/// </summary>
[TestClass]
public sealed class CryptoServiceExtensionsTests
{
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
