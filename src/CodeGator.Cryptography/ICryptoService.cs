
namespace CodeGator.Cryptography;

/// <summary>
/// This interface represents an object that performs cryptographic operations.
/// </summary>
public interface ICryptoService
{
    /// <summary>
    /// This method generates a random <see cref="KeyAndIV"/> for AES operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The returned key and IV are suitable for the AES operations on this service
    /// (256-bit key, 128-bit block).
    /// </para>
    /// </remarks>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task that returns a new <see cref="KeyAndIV"/> instance.</returns>
    /// <exception cref="ServiceException">This exception is thrown whenever the service
    /// fails to complete the operation.</exception>
    Task<KeyAndIV> GenerateKeyAndIVAsync(
        CancellationToken cancellationToken = default
        );

    /// <summary>
    /// This method derives a key and IV from a password using RFC2898 (PBKDF2).
    /// </summary>
    /// <remarks>
    /// <para>
    /// A random salt is generated; the hash algorithm name defaults to SHA512 when not
    /// specified, and iteration counts below 10,000 are raised to 10,000.
    /// </para>
    /// </remarks>
    /// <param name="password">The password to use for the operation.</param>
    /// <param name="hashAlgorithmName">The hash algorithm to use for the operation.</param>
    /// <param name="rfc2898Iterations">The number of iterations to use for the RFC2898
    /// algorithm.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task that returns a <see cref="KeyAndIV"/> derived from the password.
    /// </returns>
    /// <exception cref="ArgumentException">This exception is thrown whenever one or more
    /// arguments are missing or invalid.</exception>
    /// <exception cref="ServiceException">This exception is thrown whenever the service
    /// fails to complete the operation.</exception>
    Task<KeyAndIV> GenerateKeyAndIVAsync(
        [NotNull] string password,
        [NotNull] string hashAlgorithmName = "SHA512",
        int rfc2898Iterations = 10000,
        CancellationToken cancellationToken = default
        );

    /// <summary>
    /// This method derives a key and IV from a password and salt using RFC2898.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The hash algorithm name defaults to SHA512 when not specified, and iteration counts
    /// below 10,000 are raised to 10,000.
    /// </para>
    /// </remarks>
    /// <param name="password">The password to use for the operation.</param>
    /// <param name="salt">The salt to use for the operation.</param>
    /// <param name="hashAlgorithmName">The hash algorithm to use for the operation.</param>
    /// <param name="rfc2898Iterations">The number of iterations to use for the RFC2898
    /// algorithm.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task that returns a <see cref="KeyAndIV"/> derived from the inputs.
    /// </returns>
    /// <exception cref="ArgumentException">This exception is thrown whenever one or more
    /// arguments are missing or invalid.</exception>
    /// <exception cref="ServiceException">This exception is thrown whenever the service
    /// fails to complete the operation.</exception>
    Task<KeyAndIV> GenerateKeyAndIVAsync(
        [NotNull] string password,
        [NotNull] string salt,
        [NotNull] string hashAlgorithmName = "SHA512",
        int rfc2898Iterations = 10000,
        CancellationToken cancellationToken = default
        );

    /// <summary>
    /// This method encrypts plain bytes using AES.
    /// </summary>
    /// <param name="keyAndIV">The key and IV to use for the operation.</param>
    /// <param name="plainBytes">The plain value to use for the operation.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task that returns the encrypted bytes.</returns>
    /// <exception cref="ArgumentException">This exception is thrown whenever one or more
    /// arguments are missing or invalid.</exception>
    /// <exception cref="ServiceException">This exception is thrown whenever the service
    /// fails to complete properly.</exception>
    Task<byte[]> AesEncryptAsync(
        [NotNull] KeyAndIV keyAndIV,
        [AllowNull] byte[] plainBytes,
        CancellationToken cancellationToken = default
        );

    /// <summary>
    /// This method decrypts cipher bytes using AES.
    /// </summary>
    /// <param name="keyAndIV">The key and IV to use for the operation.</param>
    /// <param name="cipherBytes">The cipher value to use for the operation.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task that returns the decrypted bytes.</returns>
    /// <exception cref="ArgumentException">This exception is thrown whenever one or more
    /// arguments are missing or invalid.</exception>
    /// <exception cref="ServiceException">This exception is thrown whenever the service
    /// fails to complete properly.</exception>
    Task<byte[]> AesDecryptAsync(
        [NotNull] KeyAndIV keyAndIV,
        [AllowNull] byte[] cipherBytes,
        CancellationToken cancellationToken = default
        );

    /// <summary>
    /// This method encrypts plain text using AES.
    /// </summary>
    /// <param name="keyAndIV">The key and IV to use for the operation.</param>
    /// <param name="plainText">The plain text to use for the operation.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task that returns the encrypted text (Base64).</returns>
    /// <exception cref="ArgumentException">This exception is thrown whenever one or more
    /// arguments are missing or invalid.</exception>
    /// <exception cref="ServiceException">This exception is thrown whenever the service
    /// fails to complete properly.</exception>
    Task<string> AesEncryptAsync(
        [NotNull] KeyAndIV keyAndIV,
        [AllowNull] string plainText,
        CancellationToken cancellationToken = default
        );

    /// <summary>
    /// This method decrypts cipher text using AES.
    /// </summary>
    /// <param name="keyAndIV">The key and IV to use for the operation.</param>
    /// <param name="cipherText">The cipher text to use for the operation.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task that returns the decrypted text.</returns>
    /// <exception cref="ArgumentException">This exception is thrown whenever one or more
    /// arguments are missing or invalid.</exception>
    /// <exception cref="ServiceException">This exception is thrown whenever the service
    /// fails to complete properly.</exception>
    Task<string> AesDecryptAsync(
        [NotNull] KeyAndIV keyAndIV,
        [AllowNull] string cipherText,
        CancellationToken cancellationToken = default
        );

    /// <summary>
    /// This method encrypts a plain stream into a cipher stream using AES.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The incoming and outgoing streams are not repositioned or closed by this method.
    /// </para>
    /// </remarks>
    /// <param name="keyAndIV">The key and IV to use for the operation.</param>
    /// <param name="plainStream">The (incoming) plain stream to use for the operation.</param>
    /// <param name="cypherStream">The (outgoing) cipher stream to use for the operation.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task that performs the operation.</returns>
    /// <exception cref="ArgumentException">This exception is thrown whenever one or more
    /// arguments are missing or invalid.</exception>
    /// <exception cref="ServiceException">This exception is thrown whenever the service
    /// fails to complete properly.</exception>
    Task AesEncryptAsync(
        [NotNull] KeyAndIV keyAndIV,
        [NotNull] Stream plainStream,
        [NotNull] Stream cypherStream,
        CancellationToken cancellationToken = default
        );

    /// <summary>
    /// This method decrypts a cipher stream into a plain stream using AES.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The incoming and outgoing streams are not repositioned or closed by this method.
    /// </para>
    /// </remarks>
    /// <param name="keyAndIV">The key and IV to use for the operation.</param>
    /// <param name="cypherStream">The (incoming) cipher stream to use for the operation.</param>
    /// <param name="plainStream">The (outgoing) plain stream to use for the operation.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task that performs the operation.</returns>
    /// <exception cref="ArgumentException">This exception is thrown whenever one or more
    /// arguments are missing or invalid.</exception>
    /// <exception cref="ServiceException">This exception is thrown whenever the service
    /// fails to complete properly.</exception>
    Task AesDecryptAsync(
        [NotNull] KeyAndIV keyAndIV,
        [NotNull] Stream cypherStream,
        [NotNull] Stream plainStream,        
        CancellationToken cancellationToken = default
        );
}
