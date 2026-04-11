
namespace CodeGator.Cryptography;

/// <summary>
/// Unit tests for <see cref="CryptoService"/> behavior beyond round-trip encrypt/decrypt.
/// </summary>
[TestClass]
public sealed class CryptoServiceTests
{
    private static CryptoService CreateService()
    {
        var logger = new Mock<ILogger<CryptoService>>();
        return new CryptoService(
            RandomNumberGenerator.Create(),
            logger.Object
            );
    }

    #region Key generation

    [TestCategory("Unit")]
    [TestMethod]
    public async Task GenerateKeyAndIV_Random_ReturnsAes256KeyAndBlockSizedIv()
    {
        var service = CreateService();

        var keyAndIV = await service.GenerateKeyAndIVAsync();

        Assert.AreEqual(32, keyAndIV.Key.Length);
        Assert.AreEqual(16, keyAndIV.IV.Length);
    }

    [TestCategory("Unit")]
    [TestMethod]
    public async Task GenerateKeyAndIV_WithPasswordAndSalt_IsDeterministic()
    {
        var service = CreateService();

        var first = await service.GenerateKeyAndIVAsync(
            "correct horse battery staple",
            "fixed-salt",
            "SHA512",
            10000
            );

        var second = await service.GenerateKeyAndIVAsync(
            "correct horse battery staple",
            "fixed-salt",
            "SHA512",
            10000
            );

        CollectionAssert.AreEqual(first.Key, second.Key);
        CollectionAssert.AreEqual(first.IV, second.IV);
    }

    [TestCategory("Unit")]
    [TestMethod]
    public async Task GenerateKeyAndIV_IterationsBelowMinimum_UseTenThousand()
    {
        var service = CreateService();

        var withLowIterations = await service.GenerateKeyAndIVAsync(
            "same-password",
            "same-salt",
            "SHA512",
            5000
            );

        var withTenThousand = await service.GenerateKeyAndIVAsync(
            "same-password",
            "same-salt",
            "SHA512",
            10000
            );

        CollectionAssert.AreEqual(withTenThousand.Key, withLowIterations.Key);
        CollectionAssert.AreEqual(withTenThousand.IV, withLowIterations.IV);
    }

    [TestCategory("Unit")]
    [TestMethod]
    public async Task GenerateKeyAndIV_NullPassword_ThrowsArgumentException()
    {
        var service = CreateService();

        await Assert.ThrowsExactlyAsync<ArgumentException>(
            () => service.GenerateKeyAndIVAsync(
                null!,
                "salt",
                "SHA512"
                )
            );
    }

    #endregion

    #region AES bytes and strings

    [TestCategory("Unit")]
    [TestMethod]
    public async Task AesEncrypt_NullOrEmptyPlainBytes_ReturnsEmptyArray()
    {
        var service = CreateService();
        var keyAndIV = await service.GenerateKeyAndIVAsync("pw", "salt", "SHA512");

        var nullResult = await service.AesEncryptAsync(keyAndIV, (byte[]?)null);
        var emptyResult = await service.AesEncryptAsync(keyAndIV, Array.Empty<byte>());

        Assert.AreEqual(0, nullResult.Length);
        Assert.AreEqual(0, emptyResult.Length);
    }

    [TestCategory("Unit")]
    [TestMethod]
    public async Task AesDecrypt_NullOrEmptyCipherBytes_ReturnsEmptyArray()
    {
        var service = CreateService();
        var keyAndIV = await service.GenerateKeyAndIVAsync("pw", "salt", "SHA512");

        var nullResult = await service.AesDecryptAsync(keyAndIV, (byte[]?)null);
        var emptyResult = await service.AesDecryptAsync(keyAndIV, Array.Empty<byte>());

        Assert.AreEqual(0, nullResult.Length);
        Assert.AreEqual(0, emptyResult.Length);
    }

    [TestCategory("Unit")]
    [TestMethod]
    public async Task AesEncrypt_NullOrEmptyPlainText_ReturnsEmptyString()
    {
        var service = CreateService();
        var keyAndIV = await service.GenerateKeyAndIVAsync("pw", "salt", "SHA512");

        var nullResult = await service.AesEncryptAsync(keyAndIV, (string?)null);
        var emptyResult = await service.AesEncryptAsync(keyAndIV, string.Empty);

        Assert.AreEqual(string.Empty, nullResult);
        Assert.AreEqual(string.Empty, emptyResult);
    }

    [TestCategory("Unit")]
    [TestMethod]
    public async Task AesDecrypt_NullOrEmptyCipherText_ReturnsEmptyString()
    {
        var service = CreateService();
        var keyAndIV = await service.GenerateKeyAndIVAsync("pw", "salt", "SHA512");

        var nullResult = await service.AesDecryptAsync(keyAndIV, (string?)null);
        var emptyResult = await service.AesDecryptAsync(keyAndIV, string.Empty);

        Assert.AreEqual(string.Empty, nullResult);
        Assert.AreEqual(string.Empty, emptyResult);
    }

    [TestCategory("Unit")]
    [TestMethod]
    public async Task AesEncrypt_InvalidKeyLength_ThrowsArgumentException()
    {
        var service = CreateService();
        var keyAndIV = new KeyAndIV
        {
            Key = new byte[16],
            IV = new byte[16]
        };

        await Assert.ThrowsExactlyAsync<ArgumentException>(
            () => service.AesEncryptAsync(keyAndIV, new byte[] { 1, 2, 3 })
            );
    }

    [TestCategory("Unit")]
    [TestMethod]
    public async Task AesDecrypt_InvalidBase64_ThrowsServiceException()
    {
        var service = CreateService();
        var keyAndIV = await service.GenerateKeyAndIVAsync("pw", "salt", "SHA512");

        var ex = await Assert.ThrowsExactlyAsync<ServiceException>(
            () => service.AesDecryptAsync(keyAndIV, "not-valid-base64!!!")
            );

        Assert.IsNotNull(ex.InnerException);
    }

    #endregion

    #region Streams

    [TestCategory("Unit")]
    [TestMethod]
    public async Task AesEncrypt_EmptyPlainStream_DoesNotWriteOutput()
    {
        var service = CreateService();
        var keyAndIV = await service.GenerateKeyAndIVAsync("pw", "salt", "SHA512");

        using var plain = new MemoryStream();
        using var cipher = new MemoryStream();

        await service.AesEncryptAsync(keyAndIV, plain, cipher);

        Assert.AreEqual(0, cipher.Length);
    }

    [TestCategory("Unit")]
    [TestMethod]
    public async Task AesDecrypt_EmptyCipherStream_LeavesPlainStreamEmpty()
    {
        var service = CreateService();
        var keyAndIV = await service.GenerateKeyAndIVAsync("pw", "salt", "SHA512");

        using var cipher = new MemoryStream();
        using var plain = new MemoryStream();

        await service.AesDecryptAsync(keyAndIV, cipher, plain);

        Assert.AreEqual(0, plain.Length);
    }

    #endregion
}
