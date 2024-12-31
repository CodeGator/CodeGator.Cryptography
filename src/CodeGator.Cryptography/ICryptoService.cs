
namespace CodeGator.Cryptography;

/// <summary>
/// This interface represents an object that performs cryptographic operations.
/// </summary>
public interface ICryptoService
{
    /// <summary>
    /// This method generates a <see cref="KeyAndIV"/> object containing a 
    /// random Key and IV.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task to perform the operation that returns a <see cref="KeyAndIV"/>
    /// object.</returns>
    /// <exception cref="ServiceException">This exception is thrown 
    /// whenever the service fails to complete the operation.</exception>
    Task<KeyAndIV> GenerateKeyAndIVAsync(
        CancellationToken cancellationToken = default
        );

    /// <summary>
    /// This method generates a <see cref="KeyAndIV"/> object containing a Key
    /// and IV that are generated using the RFC2898 algorithm with a the given
    /// password and a random SALT value.
    /// </summary>
    /// <param name="password">The password to use for the operation.</param>
    /// <param name="hashAlgorithmName">The hash algorithm to use for the operation.</param>
    /// <param name="rfc2898Iterations">The number of iterations to use for the
    /// RFC2898 algorithm.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task to perform the operation that returns a <see cref="KeyAndIV"/>
    /// object.</returns>
    /// <exception cref="ArgumentException">This exception is thrown whenever 
    /// one or more arguments is missing, or invalid.</exception>
    /// <exception cref="ServiceException">This exception is thrown 
    /// whenever the service fails to complete the operation.</exception>
    Task<KeyAndIV> GenerateKeyAndIVAsync(
        [NotNull] string password,
        [NotNull] string hashAlgorithmName = "SHA512",
        int rfc2898Iterations = 10000,
        CancellationToken cancellationToken = default
        );

    /// <summary>
    /// This method generates a <see cref="KeyAndIV"/> object containing a Key
    /// and IV that are generated using the RFC2898 algorithm with the given 
    /// password and SALT value.
    /// </summary>
    /// <param name="password">The password to use for the operation.</param>
    /// <param name="salt">The salt to use for the operation.</param>
    /// <param name="hashAlgorithmName">The hash algorithm to use for the operation.</param>
    /// <param name="rfc2898Iterations">The number of iterations to use for the
    /// RFC2898 algorithm.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task to perform the operation that returns a <see cref="KeyAndIV"/>
    /// object.</returns>
    /// <exception cref="ArgumentException">This exception is thrown whenever 
    /// one or more arguments is missing, or invalid.</exception>
    /// <exception cref="ServiceException">This exception is thrown 
    /// whenever the service fails to complete the operation.</exception>
    Task<KeyAndIV> GenerateKeyAndIVAsync(
        [NotNull] string password,
        [NotNull] string salt,
        [NotNull] string hashAlgorithmName = "SHA512",
        int rfc2898Iterations = 10000,
        CancellationToken cancellationToken = default
        );

    /// <summary>
    /// This method encrypts the given bytes using AES.
    /// </summary>
    /// <param name="keyAndIV">The key and IV to use for the operation.</param>
    /// <param name="plainBytes">The plain value to use for the operation.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task to perform the operation that returns the encrypted 
    /// bytes.</returns>
    /// <exception cref="ArgumentException">This exception is thrown whenever
    /// one or more arguments are missing, or invalid.</exception>
    /// <exception cref="ServiceException">This exception is thrown 
    /// whenever the service fails to complete properly.</exception>
    Task<byte[]> AesEncryptAsync(
        [NotNull] KeyAndIV keyAndIV,
        [AllowNull] byte[] plainBytes,
        CancellationToken cancellationToken = default
        );

    /// <summary>
    /// This method decrypts the given bytes using AES.
    /// </summary>
    /// <param name="keyAndIV">The key and IV to use for the operation.</param>
    /// <param name="cipherBytes">The cypher value to use for the operation.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task to perform the operation that returns the decrypted 
    /// bytes.</returns>
    /// <exception cref="ArgumentException">This exception is thrown whenever
    /// one or more arguments are missing, or invalid.</exception>
    /// <exception cref="ServiceException">This exception is thrown 
    /// whenever the service fails to complete properly.</exception>
    Task<byte[]> AesDecryptAsync(
        [NotNull] KeyAndIV keyAndIV,
        [AllowNull] byte[] cipherBytes,
        CancellationToken cancellationToken = default
        );

    /// <summary>
    /// This method encrypts the given text using AES.
    /// </summary>
    /// <param name="keyAndIV">The key and IV to use for the operation.</param>
    /// <param name="plainText">The plain text to use for the operation.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task to perform the operation that returns the encrypted 
    /// text.</returns>
    /// <exception cref="ArgumentException">This exception is thrown whenever
    /// one or more arguments are missing, or invalid.</exception>
    /// <exception cref="ServiceException">This exception is thrown 
    /// whenever the service fails to complete properly.</exception>
    Task<string> AesEncryptAsync(
        [NotNull] KeyAndIV keyAndIV,
        [AllowNull] string plainText,
        CancellationToken cancellationToken = default
        );

    /// <summary>
    /// This method decrypts the given text using AES.
    /// </summary>
    /// <param name="keyAndIV">The key and IV to use for the operation.</param>
    /// <param name="cipherText">The cypher text to use for the operation.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task to perform the operation that returns the decrypted 
    /// text.</returns>
    /// <exception cref="ArgumentException">This exception is thrown whenever
    /// one or more arguments are missing, or invalid.</exception>
    /// <exception cref="ServiceException">This exception is thrown 
    /// whenever the service fails to complete properly.</exception>
    Task<string> AesDecryptAsync(
        [NotNull] KeyAndIV keyAndIV,
        [AllowNull] string cipherText,
        CancellationToken cancellationToken = default
        );

    /// <summary>
    /// This method encrypts the given stream using AES.
    /// </summary>
    /// <param name="keyAndIV">The key and IV to use for the operation.</param>
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
    Task AesEncryptAsync(
        [NotNull] KeyAndIV keyAndIV,
        [NotNull] Stream plainStream,
        [NotNull] Stream cypherStream,
        CancellationToken cancellationToken = default
        );

    /// <summary>
    /// This method decrypts the given stream using AES.
    /// </summary>
    /// <param name="keyAndIV">The key and IV to use for the operation.</param>
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
    Task AesDecryptAsync(
        [NotNull] KeyAndIV keyAndIV,
        [NotNull] Stream cypherStream,
        [NotNull] Stream plainStream,        
        CancellationToken cancellationToken = default
        );
}
