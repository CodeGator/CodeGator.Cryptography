
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
    /// This method ensures the <see cref="CryptoService"/> class can correctly
    /// encrypt and decrypt a byte array.
    /// </summary>
    /// <returns>A task to perform the operation.</returns>
    [TestCategory("Unit")]
    [TestMethod]
    public async Task EncryptDecryptBytesWorksTogether()
    {
        var logger = new Mock<ILogger<CryptoService>>();

        var service = new CryptoService(
            RandomNumberGenerator.Create(),
            logger.Object
            );

        var keyAndIV = await service.GenerateKeyFromPasswordAsync(
            "super secret password"
            );

        var originalBytes = RandomNumberGenerator.GetBytes(149);

        var encryptedBytes = await service.AesEncryptAsync(
            keyAndIV,
            originalBytes
            );

        var decryptedBytes = await service.AesDecryptAsync(
            keyAndIV,
            encryptedBytes
            );

        Assert.IsFalse(originalBytes.LongLength == encryptedBytes.LongLength);
        Assert.IsTrue(originalBytes.LongLength == decryptedBytes.LongLength);

        for (var x = 0; x < originalBytes.LongLength; x++)
        {
            Assert.IsTrue(originalBytes[x] == decryptedBytes[x]);
        }
    }

    // *******************************************************************

    /// <summary>
    /// This method ensures the <see cref="CryptoService"/> class can correctly
    /// encrypt and decrypt a string.
    /// </summary>
    /// <returns>A task to perform the operation.</returns>
    [TestCategory("Unit")]
    [TestMethod]
    public async Task EncryptDecryptStringWorksTogether()
    {
        var logger = new Mock<ILogger<CryptoService>>();

        var service = new CryptoService(
            RandomNumberGenerator.Create(),
            logger.Object
            );

        var keyAndIV = await service.GenerateKeyFromPasswordAsync(
            "super secret password"
            );

        var originalText = RandomNumberGenerator.GetHexString(32);

        var encryptedText = await service.AesEncryptAsync(
            keyAndIV,
            originalText
            );

        var decryptedText = await service.AesDecryptAsync(
            keyAndIV,
            encryptedText
            );

        Assert.IsFalse(originalText.Length == encryptedText.Length);
        Assert.IsTrue(originalText.Length == decryptedText.Length);
        Assert.IsTrue(originalText == decryptedText);
    }

    #endregion
}
