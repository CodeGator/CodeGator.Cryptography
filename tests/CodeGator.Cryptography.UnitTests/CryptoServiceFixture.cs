
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
    /// This method ensures that the <see cref="CryptoService.AesEncryptAsync(KeyAndIV, byte[], CancellationToken)"/>
    /// and <see cref="CryptoService.AesDecryptAsync(KeyAndIV, string?, CancellationToken)"/>
    /// methods work together to encrypt a byte array and then 
    /// decrypt that byte array back to the original data.
    /// </summary>
    /// <returns></returns>
    [TestCategory("Unit")]
    [TestMethod]
    public async Task EncryptDecryptBytesWorkTogether()
    {
        var logger = new Mock<ILogger<CryptoService>>();

        var service = new CryptoService(
            RandomNumberGenerator.Create(),
            logger.Object
            );

        var keyAndIV = await service.GenerateKeyAndIVAsync();

        var originalBytes = RandomNumberGenerator.GetBytes(256);

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

    #endregion
}
