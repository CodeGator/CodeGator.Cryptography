
namespace CodeGator.Cryptography;

/// <summary>
/// This interface represents an object that performs cryptographic operations.
/// </summary>
public interface ICryptoService
{
    /// <summary>
    /// This method generates a Key and IV from the given password and salt.
    /// </summary>
    /// <param name="password">The password to use for the operation.</param>
    /// <param name="salt">The salt to use for the operation.</param>
    /// <param name="hashAlgorithmName">The hash algorithm to use for the operation.</param>
    /// <param name="rfc2898Iterations">The number of iterations to use for the
    /// RFC2898 algorithm.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task to perform the operation that returns a cryptographic
    /// key and IV value, in a tuple, as: (key, IV).</returns>
    /// <exception cref="ArgumentException">This exception is thrown whenever 
    /// one or more arguments is missing, or invalid.</exception>
    /// <exception cref="ServiceException">This exception is thrown 
    /// whenever the service fails to complete the operation.</exception>
    Task<KeyAndIV> GenerateKeyAndIVAsync(
        [NotNull] string password,
        [NotNull] string salt,
        [NotNull] string hashAlgorithmName = "SHA512",
        int rfc2898Iterations = 15000,
        CancellationToken cancellationToken = default
        );

    /// <summary>
    /// This method generates a random Key and IV.
    /// </summary>
    /// <param name="hashAlgorithmName">The hash algorithm to use for the operation.</param>
    /// <param name="rfc2898Iterations">The number of iterations to use for the
    /// RFC2898 algorithm.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task to perform the operation that returns a cryptographic
    /// key and IV value, in a tuple, as: (key, IV).</returns>
    /// <exception cref="ArgumentException">This exception is thrown whenever 
    /// one or more arguments is missing, or invalid.</exception>
    /// <exception cref="ServiceException">This exception is thrown 
    /// whenever the service fails to complete the operation.</exception>
    Task<KeyAndIV> GenerateKeyAndIVAsync(
        [NotNull] string hashAlgorithmName = "SHA512",
        int rfc2898Iterations = 15000,
        CancellationToken cancellationToken = default
        );

    /// <summary>
    /// This method encrypts the given string using AES.
    /// </summary>
    /// <param name="keyAndIV">The key and IV to use for the operation.</param>
    /// <param name="value">The value to use for the operation.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task to perform the operation that returns the encrypted 
    /// string.</returns>
    /// <exception cref="ArgumentException">This exception is thrown whenever
    /// one or more arguments are missing, or invalid.</exception>
    /// <exception cref="ServiceException">This exception is thrown 
    /// whenever the service fails to complete properly.</exception>
    Task<string> AesEncryptAsync(
        [NotNull] KeyAndIV keyAndIV,
        [AllowNull] string? value,
        CancellationToken cancellationToken = default
        );

    /// <summary>
    /// This method encrypts the given string using AES.
    /// </summary>
    /// <param name="key">The key to use for the operation.</param>
    /// <param name="iv">The IV to use for the operation.</param>
    /// <param name="value">The value to use for the operation.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task to perform the operation that returns the encrypted 
    /// string.</returns>
    /// <exception cref="ArgumentException">This exception is thrown whenever
    /// one or more arguments are missing, or invalid.</exception>
    /// <exception cref="ServiceException">This exception is thrown 
    /// whenever the service fails to complete properly.</exception>
    Task<string> AesEncryptAsync(
        [NotNull] byte[] key,
        [NotNull] byte[] iv,
        [AllowNull] string? value,
        CancellationToken cancellationToken = default
        );

    /// <summary>
    /// This method encrypts the given bytes using AES.
    /// </summary>
    /// <param name="keyAndIV">The key and IV to use for the operation.</param>
    /// <param name="value">The value to use for the operation.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task to perform the operation that returns the encrypted 
    /// bytes.</returns>
    /// <exception cref="ArgumentException">This exception is thrown whenever
    /// one or more arguments are missing, or invalid.</exception>
    /// <exception cref="ServiceException">This exception is thrown 
    /// whenever the service fails to complete properly.</exception>
    Task<byte[]> AesEncryptAsync(
        [NotNull] KeyAndIV keyAndIV,
        [AllowNull] byte[]? value,
        CancellationToken cancellationToken = default
        );

    /// <summary>
    /// This method encrypts the given bytes using AES.
    /// </summary>
    /// <param name="key">The key to use for the operation.</param>
    /// <param name="iv">The IV to use for the operation.</param>
    /// <param name="value">The value to use for the operation.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task to perform the operation that returns the encrypted 
    /// bytes.</returns>
    /// <exception cref="ArgumentException">This exception is thrown whenever
    /// one or more arguments are missing, or invalid.</exception>
    /// <exception cref="ServiceException">This exception is thrown 
    /// whenever the service fails to complete properly.</exception>
    Task<byte[]> AesEncryptAsync(
        [NotNull] byte[] key,
        [NotNull] byte[] iv,
        [AllowNull] byte[]? value,
        CancellationToken cancellationToken = default
        );

    /// <summary>
    /// This method decrypts the given bytes using AES.
    /// </summary>
    /// <param name="keyAndIV">The key and IV to use for the operation.</param>
    /// <param name="value">The value to use for the operation.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task to perform the operation that returns the encrypted 
    /// bytes.</returns>
    /// <exception cref="ArgumentException">This exception is thrown whenever
    /// one or more arguments are missing, or invalid.</exception>
    /// <exception cref="ServiceException">This exception is thrown 
    /// whenever the service fails to complete properly.</exception>
    Task<byte[]> AesDecryptAsync(
        [NotNull] KeyAndIV keyAndIV,
        [AllowNull] byte[]? value,
        CancellationToken cancellationToken = default
        );

    /// <summary>
    /// This method decrypts the given bytes using AES.
    /// </summary>
    /// <param name="key">The key to use for the operation.</param>
    /// <param name="iv">The IV to use for the operation.</param>
    /// <param name="value">The value to use for the operation.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task to perform the operation that returns the encrypted 
    /// bytes.</returns>
    /// <exception cref="ArgumentException">This exception is thrown whenever
    /// one or more arguments are missing, or invalid.</exception>
    /// <exception cref="ServiceException">This exception is thrown 
    /// whenever the service fails to complete properly.</exception>
    Task<byte[]> AesDecryptAsync(
        [NotNull] byte[] key,
        [NotNull] byte[] iv,
        [AllowNull] byte[]? value,
        CancellationToken cancellationToken = default
        );

    /// <summary>
    /// This method decrypts the given string using AES.
    /// </summary>
    /// <param name="keyAndIV">The key and IV to use for the operation.</param>
    /// <param name="value">The value to use for the operation.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task to perform the operation that returns the encrypted 
    /// string.</returns>
    /// <exception cref="ArgumentException">This exception is thrown whenever
    /// one or more arguments are missing, or invalid.</exception>
    /// <exception cref="ServiceException">This exception is thrown 
    /// whenever the service fails to complete properly.</exception>
    Task<string> AesDecryptAsync(
        [NotNull] KeyAndIV keyAndIV,
        [AllowNull] string? value,
        CancellationToken cancellationToken = default
        );

    /// <summary>
    /// This method decrypts the given string using AES.
    /// </summary>
    /// <param name="key">The key to use for the operation.</param>
    /// <param name="iv">The IV to use for the operation.</param>
    /// <param name="value">The value to use for the operation.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task to perform the operation that returns the encrypted 
    /// string.</returns>
    /// <exception cref="ArgumentException">This exception is thrown whenever
    /// one or more arguments are missing, or invalid.</exception>
    /// <exception cref="ServiceException">This exception is thrown 
    /// whenever the service fails to complete properly.</exception>
    Task<string> AesDecryptAsync(
        [NotNull] byte[] key,
        [NotNull] byte[] iv,
        [AllowNull] string? value,
        CancellationToken cancellationToken = default
        );
}
