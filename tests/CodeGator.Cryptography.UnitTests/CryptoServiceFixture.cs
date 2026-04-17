
namespace CodeGator.Cryptography;

/// <summary>
/// This class is a unit test fixture for the <see cref="CryptoService"/>
/// class.
/// </summary>
[TestClass]
public sealed class CryptoServiceFixture
{
    // *******************************************************************
    // Public methods.
    // *******************************************************************

    #region Public methods

    /// <summary>
    /// This method verifies byte array encryption and decryption round-trip.
    /// </summary>
    /// <remarks>
    /// <para>Exercises <see cref="CryptoService"/> with a password-derived key.</para>
    /// </remarks>
    /// <returns>A task that represents the asynchronous test operation.</returns>
    [TestCategory("Unit")]
    [TestMethod]
    public async Task EncryptDecryptBytesWorksTogether()
    {
        var logger = new Mock<ILogger<CryptoService>>();

        var service = new CryptoService(
            RandomNumberGenerator.Create(),
            logger.Object
            );

        var keyAndIV = await service.GenerateKeyAndIVAsync(
            "super secret password"
            );

        var originalBytes = RandomNumberGenerator.GetBytes(149);

        var cypherBytes = await service.AesEncryptAsync(
            keyAndIV,
            originalBytes
            );

        var plainBytes = await service.AesDecryptAsync(
            keyAndIV,
            cypherBytes
            );

        Assert.IsFalse(originalBytes.LongLength == cypherBytes.LongLength);
        Assert.IsTrue(originalBytes.LongLength == plainBytes.LongLength);

        for (var x = 0; x < originalBytes.LongLength; x++)
        {
            Assert.IsTrue(originalBytes[x] == plainBytes[x]);
        }
    }

    // *******************************************************************

    /// <summary>
    /// This method verifies string encryption and decryption round-trip.
    /// </summary>
    /// <remarks>
    /// <para>Exercises <see cref="CryptoService"/> with a password-derived key.</para>
    /// </remarks>
    /// <returns>A task that represents the asynchronous test operation.</returns>
    [TestCategory("Unit")]
    [TestMethod]
    public async Task EncryptDecryptStringWorksTogether()
    {
        var logger = new Mock<ILogger<CryptoService>>();

        var service = new CryptoService(
            RandomNumberGenerator.Create(),
            logger.Object
            );

        var keyAndIV = await service.GenerateKeyAndIVAsync(
            "super secret password"
            );

        var originalText = RandomNumberGenerator.GetHexString(32);

        var cypherText = await service.AesEncryptAsync(
            keyAndIV,
            originalText
            );

        var plainText = await service.AesDecryptAsync(
            keyAndIV,
            cypherText
            );

        Assert.IsFalse(originalText.Length == cypherText.Length);
        Assert.IsTrue(originalText.Length == plainText.Length);
        Assert.IsTrue(originalText == plainText);
    }

    // *******************************************************************

    /// <summary>
    /// This method verifies stream encryption and decryption round-trip.
    /// </summary>
    /// <remarks>
    /// <para>Exercises <see cref="CryptoService"/> with a password-derived key.</para>
    /// </remarks>
    /// <returns>A task that represents the asynchronous test operation.</returns>
    [TestCategory("Unit")]
    [TestMethod]
    public async Task EncryptDecryptStreamWorksTogether()
    {
        var logger = new Mock<ILogger<CryptoService>>();

        var service = new CryptoService(
            RandomNumberGenerator.Create(),
            logger.Object
            );

        var keyAndIV = await service.GenerateKeyAndIVAsync(
            "super secret password"
            );

        using var originalStream = new MemoryStream(
            RandomNumberGenerator.GetBytes(149)
            );

        using var cypherStream = new MemoryStream();

        using var plainStream = new MemoryStream();

        await service.AesEncryptAsync(
            keyAndIV,
            originalStream,
            cypherStream
            );

        originalStream.Seek( 0, SeekOrigin.Begin );
        cypherStream.Seek(0, SeekOrigin.Begin);

        await service.AesDecryptAsync(
            keyAndIV,
            cypherStream,
            plainStream
            );

        plainStream.Seek(0, SeekOrigin.Begin);

        Assert.IsFalse(originalStream.Length == cypherStream.Length);
        Assert.IsTrue(originalStream.Length == plainStream.Length);

        for (var x = 0; x < originalStream.Length; x++)
        {
            Assert.IsTrue(originalStream.ReadByte() == plainStream.ReadByte());
        }
    }

    #endregion
}
