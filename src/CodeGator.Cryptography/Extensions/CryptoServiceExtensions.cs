

namespace CodeGator.Cryptography;

/// <summary>
/// This class utility contains extension methods related to the <see cref="ICryptoService"/>
/// type.
/// </summary>
public static partial class CryptoServiceExtensions
{
    // *******************************************************************
    // Byte array methods.
    // *******************************************************************

    #region Byte array methods

    /// <summary>
    /// This method encrypts the given bytes using AES.
    /// </summary>
    /// <param name="cryptoService">The crypto service to use for the operation.</param>
    /// <param name="key">The key to use for the operation.</param>
    /// <param name="iv">The iv to use for the operation.</param>
    /// <param name="plainBytes">The plain value to use for the operation.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task to perform the operation that returns the encrypted 
    /// bytes.</returns>
    /// <exception cref="ArgumentException">This exception is thrown whenever
    /// one or more arguments are missing, or invalid.</exception>
    /// <exception cref="ServiceException">This exception is thrown 
    /// whenever the service fails to complete properly.</exception>
    public static Task<byte[]> AesEncryptAsync(
        [NotNull] this ICryptoService cryptoService,
        [NotNull] byte[] key,
        [NotNull] byte[] iv,
        [NotNull] byte[] plainBytes,
        CancellationToken cancellationToken = default
        )
    {
        Guard.Instance().ThrowIfNull(cryptoService, nameof(cryptoService));

        var keyAndIV = new KeyAndIV()
        {
            Key = key,
            IV = iv
        };

        return cryptoService.AesEncryptAsync(
            keyAndIV,
            plainBytes,
            cancellationToken
            );
    }

    // *******************************************************************

    /// <summary>
    /// This method decrypts the given bytes using AES.
    /// </summary>
    /// <param name="cryptoService">The crypto service to use for the operation.</param>
    /// <param name="key">The key to use for the operation.</param>
    /// <param name="iv">The iv to use for the operation.</param>
    /// <param name="cypherBytes">The encrypted value to use for the operation.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task to perform the operation that returns the decrypted 
    /// bytes.</returns>
    /// <exception cref="ArgumentException">This exception is thrown whenever
    /// one or more arguments are missing, or invalid.</exception>
    /// <exception cref="ServiceException">This exception is thrown 
    /// whenever the service fails to complete properly.</exception>
    public static Task<byte[]> AesDecryptAsync(
        [NotNull] this ICryptoService cryptoService,
        [NotNull] byte[] key,
        [NotNull] byte[] iv,
        [NotNull] byte[] cypherBytes,
        CancellationToken cancellationToken = default
        )
    {
        Guard.Instance().ThrowIfNull(cryptoService, nameof(cryptoService));

        var keyAndIV = new KeyAndIV()
        {
            Key = key,
            IV = iv
        };

        return cryptoService.AesEncryptAsync(
            keyAndIV,
            cypherBytes,
            cancellationToken
            );
    }

    #endregion

    // *******************************************************************
    // String methods.
    // *******************************************************************

    #region String methods

    /// <summary>
    /// This method encrypts the given string using AES.
    /// </summary>
    /// <param name="cryptoService">The crypto service to use for the operation.</param>
    /// <param name="key">The key to use for the operation.</param>
    /// <param name="iv">The iv to use for the operation.</param>
    /// <param name="plainText">The plain value to use for the operation.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task to perform the operation that returns the encrypted 
    /// string.</returns>
    /// <exception cref="ArgumentException">This exception is thrown whenever
    /// one or more arguments are missing, or invalid.</exception>
    /// <exception cref="ServiceException">This exception is thrown 
    /// whenever the service fails to complete properly.</exception>
    public static Task<string> AesEncryptAsync(
        [NotNull] this ICryptoService cryptoService,
        [NotNull] byte[] key,
        [NotNull] byte[] iv,
        [NotNull] string plainText,
        CancellationToken cancellationToken = default
        )
    {
        Guard.Instance().ThrowIfNull(cryptoService, nameof(cryptoService));

        var keyAndIV = new KeyAndIV()
        {
            Key = key,
            IV = iv
        };

        return cryptoService.AesEncryptAsync(
            keyAndIV,
            plainText,
            cancellationToken
            );
    }

    // *******************************************************************

    /// <summary>
    /// This method decrypts the given string using AES.
    /// </summary>
    /// <param name="cryptoService">The crypto service to use for the operation.</param>
    /// <param name="key">The key to use for the operation.</param>
    /// <param name="iv">The iv to use for the operation.</param>
    /// <param name="cypherText">The encrypted value to use for the operation.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task to perform the operation that returns the decrypted 
    /// string.</returns>
    /// <exception cref="ArgumentException">This exception is thrown whenever
    /// one or more arguments are missing, or invalid.</exception>
    /// <exception cref="ServiceException">This exception is thrown 
    /// whenever the service fails to complete properly.</exception>
    public static Task<string> AesDecryptAsync(
        [NotNull] this ICryptoService cryptoService,
        [NotNull] byte[] key,
        [NotNull] byte[] iv,
        [NotNull] string cypherText,
        CancellationToken cancellationToken = default
        )
    {
        Guard.Instance().ThrowIfNull(cryptoService, nameof(cryptoService));

        var keyAndIV = new KeyAndIV()
        {
            Key = key,
            IV = iv
        };

        return cryptoService.AesEncryptAsync(
            keyAndIV,
            cypherText,
            cancellationToken
            );
    }

    #endregion

    // *******************************************************************
    // Stream methods.
    // *******************************************************************

    #region Stream methods

    /// <summary>
    /// This method encrypts the given stream using AES.
    /// </summary>
    /// <param name="cryptoService">The crypto service to use for the operation.</param>
    /// <param name="key">The key to use for the operation.</param>
    /// <param name="iv">The iv to use for the operation.</param>
    /// <param name="plainStream">The (incoming) plain stream to use for the operation.</param>
    /// <param name="cypherStream">The (outgoing) cypher stream to use for the operation.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task to perform the operation.</returns>
    /// <exception cref="ArgumentException">This exception is thrown whenever
    /// one or more arguments are missing, or invalid.</exception>
    /// <exception cref="ServiceException">This exception is thrown 
    /// whenever the service fails to complete properly.</exception>
    /// <remarks>
    /// <para>
    /// The incoming and outgoing streams are not repositioned or closed by this method.
    /// </para>
    /// </remarks>
    public static Task AesEncryptAsync(
        [NotNull] this ICryptoService cryptoService,
        [NotNull] byte[] key,
        [NotNull] byte[] iv,
        [NotNull] Stream plainStream,
        [NotNull] Stream cypherStream,
        CancellationToken cancellationToken = default
        )
    {
        Guard.Instance().ThrowIfNull(cryptoService, nameof(cryptoService));

        var keyAndIV = new KeyAndIV()
        {
            Key = key,
            IV = iv
        };

        return cryptoService.AesEncryptAsync(
            keyAndIV,
            plainStream,
            cypherStream,
            cancellationToken
            );
    }

    // *******************************************************************

    /// <summary>
    /// This method decrypts the given stream using AES.
    /// </summary>
    /// <param name="cryptoService">The crypto service to use for the operation.</param>
    /// <param name="key">The key to use for the operation.</param>
    /// <param name="iv">The iv to use for the operation.</param>
    /// <param name="cypherStream">The (incoming) cypher stream to use for the operation.</param>
    /// <param name="plainStream">The (outgoing) plain stream to use for the operation.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task to perform the operation.</returns>
    /// <exception cref="ArgumentException">This exception is thrown whenever
    /// one or more arguments are missing, or invalid.</exception>
    /// <exception cref="ServiceException">This exception is thrown 
    /// whenever the service fails to complete properly.</exception>
    /// <remarks>
    /// <para>
    /// The incoming and outgoing streams are not repositioned or closed by this method.
    /// </para>
    /// </remarks>
    public static Task AesDecryptAsync(
        [NotNull] this ICryptoService cryptoService,
        [NotNull] byte[] key,
        [NotNull] byte[] iv,
        [NotNull] Stream cypherStream,
        [NotNull] Stream plainStream,
        CancellationToken cancellationToken = default
        )
    {
        Guard.Instance().ThrowIfNull(cryptoService, nameof(cryptoService));

        var keyAndIV = new KeyAndIV()
        {
            Key = key,
            IV = iv
        };

        return cryptoService.AesEncryptAsync(
            keyAndIV,
            cypherStream,
            plainStream,
            cancellationToken
            );
    }

    #endregion
}
