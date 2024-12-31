
namespace CodeGator.Cryptography;

/// <summary>
/// This class is a default implementation of the <see cref="ICryptoService"/>
/// interface.
/// </summary>
/// <param name="randomNumberGenerator">The random number generator to use 
/// with this service.</param>
/// <param name="logger">The logger to use with this service.</param>
internal sealed class CryptoService(
    [NotNull] RandomNumberGenerator randomNumberGenerator,
    [NotNull] ILogger<CryptoService> logger
    ) : ICryptoService
{
    // *******************************************************************
    // Key and IV methods.
    // *******************************************************************

    #region Key and IV methods

    /// <inheritdoc/>
    public Task<KeyAndIV> GenerateRandomKeyAsync(
        CancellationToken cancellationToken = default
        )
    {
        try
        {
            logger.LogDebug(
                "The '{t1}' service is generating a random key and IV",
                nameof(CryptoService)
                );

            var keyAndIV = new KeyAndIV()
            {
                Key = RandomNumberGenerator.GetBytes(32),
                IV = RandomNumberGenerator.GetBytes(16)
            };

            logger.LogDebug(
                "The '{t1}' service is returning a '{t2}' byte cryptographic key " +
                "and a '{t3}' byte IV",
                nameof(CryptoService),
                keyAndIV.Key.Length,
                keyAndIV.IV.Length
                );

            return Task.FromResult(keyAndIV);
        }
        catch (Exception ex)
        {
            logger.LogError(
                ex,
                "the '{t1}' service failed to generate a random key!",
                nameof(CryptoService)
                );

            throw new ServiceException(
                message: $"Failed to generate a random key!",
                innerException: ex
                );
        }
    }

    // *******************************************************************

    /// <inheritdoc/>
    public Task<KeyAndIV> GenerateRandomKeyAsync(
        [NotNull] string password,
        [NotNull] string hashAlgorithmName = "SHA512",
        int rfc2898Iterations = 10000,
        CancellationToken cancellationToken = default
        )
    {
        Guard.Instance().ThrowIfNullOrEmpty(password, nameof(password))
            .ThrowIfNullOrEmpty(hashAlgorithmName, nameof(hashAlgorithmName));

        try
        {
            if (rfc2898Iterations < 10000)
            {
                logger.LogDebug(
                    "The '{t1}' service is set the RFC2898 iterations to " +
                    "to a default value, since they were less than 10,000",
                    nameof(CryptoService)
                    );
                rfc2898Iterations = 10000;
            }            

            logger.LogDebug(
                "The '{t1}' service is generating an AES algorithm instance",
                nameof(CryptoService)
                );

            using var alg = Aes.Create();

            logger.LogDebug(
                "The '{t1}' service is setting the key and block sizes for AES",
                nameof(CryptoService)
                );

            alg.KeySize = 256;
            alg.BlockSize = 128;

            logger.LogDebug(
                "The '{t1}' service is converting the password to bytes",
                nameof(CryptoService)
                );

            var passwordBytes = Encoding.UTF8.GetBytes(
                password
                );

            logger.LogDebug(
                "The '{t1}' service is generating a random SALT value",
                nameof(CryptoService)
                );

            var salt = new byte[16];
            randomNumberGenerator.GetNonZeroBytes(
                salt
                );

            logger.LogDebug(
                "The '{t1}' service is creating a hash algorithm",
                nameof(CryptoService)
                );

            var hashAlgorithm = new HashAlgorithmName( 
                hashAlgorithmName 
                );

            logger.LogDebug(
                "The '{t1}' service is deriving an RFC2898 based cryptographic key and IV",
                nameof(CryptoService)
                );

            var derivedKey = new Rfc2898DeriveBytes(
                passwordBytes,
                salt,
                rfc2898Iterations,
                hashAlgorithm
            );

            var keyAndIV = new KeyAndIV()
            {
                Key = derivedKey.GetBytes(alg.KeySize / 8),
                IV = derivedKey.GetBytes(alg.BlockSize / 8)
            };

            logger.LogDebug(
                "The '{t1}' service is returning a '{t2}' byte cryptographic " +
                "key and a '{t3}' byte IV",
                nameof(CryptoService),
                keyAndIV.Key.Length,
                keyAndIV.IV.Length
                );

            return Task.FromResult(keyAndIV);
        }
        catch (Exception ex)
        {
            logger.LogError(
                ex,
                "The '{t1}' service failed to generate a key from a password!",
                nameof(CryptoService)
                );

            throw new ServiceException(
                message: $"Failed to generate a key from a password!",
                innerException: ex
                );
        }
    }

    // *******************************************************************

    /// <inheritdoc/>
    public Task<KeyAndIV> GenerateRandomKeyAsync(
        [NotNull] string password,
        [NotNull] string salt,
        [NotNull] string hashAlgorithmName = "SHA512",
        int rfc2898Iterations = 10000,
        CancellationToken cancellationToken = default
        )
    {
        Guard.Instance().ThrowIfNullOrEmpty(password, nameof(password))
            .ThrowIfNullOrEmpty(salt, nameof(salt))
            .ThrowIfNullOrEmpty(hashAlgorithmName, nameof(hashAlgorithmName));

        try
        {
            if (rfc2898Iterations < 10000)
            {
                logger.LogDebug(
                    "The '{t1}' service is set the RFC2898 iterations to " +
                    "to a default value, since they were less than 10,000",
                    nameof(CryptoService)
                    );
                rfc2898Iterations = 10000;
            }
                        
            using var alg = Aes.Create();

            logger.LogDebug(
                "The '{t1}' service is setting the key and block sizes for AES",
                nameof(CryptoService)
                );

            alg.KeySize = 256;
            alg.BlockSize = 128;

            logger.LogDebug(
                "The '{t1}' service is converting the password to bytes",
                nameof(CryptoService)
                );

            var passwordBytes = Encoding.UTF8.GetBytes(
                password
                );

            logger.LogDebug(
                "The '{t1}' service is converting the salt to bytes",
                nameof(CryptoService)
                );

            var saltBytes = Encoding.UTF8.GetBytes(
                salt
                );

            logger.LogDebug(
                "The '{t1}' service is generating an AES algorithm instance",
                nameof(CryptoService)
                );

            var hashAlgorithm = new HashAlgorithmName(
                hashAlgorithmName
                );

            logger.LogDebug(
                "The '{t1}' service is deriving an RFC2898 based cryptographic key and IV",
                nameof(CryptoService)
                );

            var derivedKey = new Rfc2898DeriveBytes(
                passwordBytes,
                saltBytes,
                rfc2898Iterations,
                hashAlgorithm
            );

            var keyAndIV = new KeyAndIV()
            {
                Key = derivedKey.GetBytes(alg.KeySize / 8),
                IV = derivedKey.GetBytes(alg.BlockSize / 8)
            };

            logger.LogDebug(
                "The '{t1}' service is returning a '{t2}' byte cryptographic " +
                "key and a '{t3}' byte IV",
                nameof(CryptoService),
                keyAndIV.Key.Length,
                keyAndIV.IV.Length
                );

            return Task.FromResult(keyAndIV);
        }
        catch (Exception ex)
        {
            logger.LogError(
                ex,
                "The '{t1}' service failed to generate a key from a " +
                "password and a salt!",
                nameof(CryptoService)
                );

            throw new ServiceException(
                message: $"Failed to generate a key from a password " +
                "and a salt!",
                innerException: ex
                );
        }
    }

    #endregion

    // *******************************************************************
    // Byte array methods.
    // *******************************************************************

    #region Byte array methods

    /// <inheritdoc/>
    public Task<byte[]> AesEncryptAsync(
        [NotNull] KeyAndIV keyAndIV,
        [AllowNull] byte[] plainValue,
        CancellationToken cancellationToken = default
        )
    {
        Guard.Instance().ThrowIfNull(keyAndIV, nameof(keyAndIV))
            .ThrowIfFalse(keyAndIV.Key.LongLength == 32, nameof(keyAndIV))
            .ThrowIfFalse(keyAndIV.IV.LongLength == 16, nameof(keyAndIV));

        try
        {
            if (plainValue is null || plainValue.Length == 0)
            {
                logger.LogDebug(
                    "The '{t1}' service is returning an empty array because " +
                    "the incoming bytes were empty.",
                    nameof(CryptoService)
                    );
                return Task.FromResult(Array.Empty<byte>());
            }

            logger.LogDebug(
                "The '{t1}' service is generating an AES algorithm instance",
                nameof(CryptoService)
                );

            using var alg = Aes.Create();

            logger.LogDebug(
                "The '{t1}' service is setting the key and block sizes for AES",
                nameof(CryptoService)
                );

            alg.KeySize = 256;
            alg.BlockSize = 128;

            logger.LogDebug(
                "The '{t1}' service is setting the key and IV values for AES",
                nameof(CryptoService)
                );

            alg.Key = keyAndIV.Key;
            alg.IV = keyAndIV.IV;

            logger.LogDebug(
                "The '{t1}' service is creating an encryptor",
                nameof(CryptoService)
                );

            using var encryptor = alg.CreateEncryptor();

            logger.LogDebug(
                "The '{t1}' service is encrypting '{t2}' bytes",
                nameof(CryptoService),
                plainValue.Length
                );

            var cipherBytes = encryptor.TransformFinalBlock(
                plainValue,
                0,
                plainValue.Length
                );

            logger.LogDebug(
                "The '{t1}' service is returning '{t2}' encrypted bytes",
                nameof(CryptoService),
                cipherBytes.Length
                );

            return Task.FromResult(cipherBytes);
        }
        catch (Exception ex)
        {
            logger.LogError(
                ex,
                "The '{t1}' service failed to encrypt a byte array!",
                nameof(CryptoService)
                );

            throw new ServiceException(
                innerException: ex,
                message: "Failed to encrypt a byte array!"
                );
        }
    }

    // *******************************************************************

    /// <inheritdoc/>
    public Task<byte[]> AesDecryptAsync(
        [NotNull] KeyAndIV keyAndIV,
        [AllowNull] byte[] cipherValue,
        CancellationToken cancellationToken = default
        )
    {
        Guard.Instance().ThrowIfNull(keyAndIV, nameof(keyAndIV))
            .ThrowIfFalse(keyAndIV.Key.LongLength == 32, nameof(keyAndIV))
            .ThrowIfFalse(keyAndIV.IV.LongLength == 16, nameof(keyAndIV));

        try
        {
            if (cipherValue is null || cipherValue.Length == 0)
            {
                logger.LogDebug(
                    "The '{t1}' service is returning an empty array because " +
                    "the incoming bytes were empty.",
                    nameof(CryptoService)
                    );
                return Task.FromResult(Array.Empty<byte>());
            }

            logger.LogDebug(
                "The '{t1}' service is generating an AES algorithm instance",
                nameof(CryptoService)
                );

            using var alg = Aes.Create();

            logger.LogDebug(
                "The '{t1}' service is setting the key and block sizes for AES",
                nameof(CryptoService)
                );

            alg.KeySize = 256;
            alg.BlockSize = 128;

            logger.LogDebug(
                "The '{t1}' service is setting the key and IV values for AES",
                nameof(CryptoService)
                );

            alg.Key = keyAndIV.Key;
            alg.IV = keyAndIV.IV;

            logger.LogDebug(
                "The '{t1}' service is creating a decryptor",
                nameof(CryptoService)
                );

            using var decryptor = alg.CreateDecryptor();

            logger.LogDebug(
                "The '{t1}' service is decrypting '{t2}' bytes",
                nameof(CryptoService),
                cipherValue.Length
                );

            var plainValue = decryptor.TransformFinalBlock(
                cipherValue,
                0,
                cipherValue.Length
                );

            logger.LogDebug(
                "The '{t1}' service is returning '{t2}' decrypted bytes",
                nameof(CryptoService),
                plainValue.Length
                );

            return Task.FromResult(plainValue);
        }
        catch (Exception ex)
        {
            logger.LogError(
                ex,
                "The '{t1}' service failed to decrypt a byte array!",
                nameof(CryptoService)
                );

            throw new ServiceException(
                innerException: ex,
                message: "Failed to decrypt a byte array!"
                );
        }
    }

    #endregion

    // *******************************************************************
    // String methods.
    // *******************************************************************

    #region String methods

    /// <inheritdoc/>
    public Task<string> AesEncryptAsync(
        [NotNull] KeyAndIV keyAndIV,
        [AllowNull] string plainText,
        CancellationToken cancellationToken = default
        )
    {
        Guard.Instance().ThrowIfNull(keyAndIV, nameof(keyAndIV))
            .ThrowIfFalse(keyAndIV.Key.LongLength == 32, nameof(keyAndIV))
            .ThrowIfFalse(keyAndIV.IV.LongLength == 16, nameof(keyAndIV));

        try
        {
            if (plainText is null || plainText.Length == 0)
            {
                logger.LogDebug(
                    "The '{t1}' service is returning an empty string because " +
                    "the incoming string was empty.",
                    nameof(CryptoService)
                    );
                return Task.FromResult(string.Empty);
            }

            logger.LogDebug(
                "The '{t1}' service is generating an AES algorithm instance",
                nameof(CryptoService)
                );

            using var alg = Aes.Create();

            logger.LogDebug(
                "The '{t1}' service is setting the key and block sizes for AES",
                nameof(CryptoService)
                );

            alg.KeySize = 256;
            alg.BlockSize = 128;

            logger.LogDebug(
                "The '{t1}' service is setting the key and IV values for AES",
                nameof(CryptoService)
                );

            alg.Key = keyAndIV.Key;
            alg.IV = keyAndIV.IV;

            logger.LogDebug(
                "The '{t1}' service is creating an encryptor",
                nameof(CryptoService)
                );

            using var encryptor = alg.CreateEncryptor();

            logger.LogDebug(
                "The '{t1}' service is converting '{t2}' characters to bytes",
                nameof(CryptoService),
                plainText.Length
                );

            var plainBytes = UTF8Encoding.UTF8.GetBytes(
                plainText
                );

            logger.LogDebug(
                "The '{t1}' service is encrypting '{t2}' bytes",
                nameof(CryptoService),
                plainBytes.Length
                );

            var cipherBytes = encryptor.TransformFinalBlock(
                plainBytes,
                0,
                plainBytes.Length
                );

            logger.LogDebug(
                "The '{t1}' service is converting '{t2}' bytes to base64",
                nameof(CryptoService),
                cipherBytes.Length
                );

            var cypherText = Convert.ToBase64String(
                cipherBytes
                );

            logger.LogDebug(
                "The '{t1}' service is returning '{t2}' encrypted characters",
                nameof(CryptoService),
                cypherText.Length
                );

            return Task.FromResult(cypherText);
        }
        catch (Exception ex)
        {
            logger.LogError(
                ex,
                "The '{t1}' service failed to encrypt a string value!",
                nameof(CryptoService)
                );

            throw new ServiceException(
                innerException: ex,
                message: "Failed to encrypt a string value!"
                );
        }
    }

    // *******************************************************************

    /// <inheritdoc/>
    public Task<string> AesDecryptAsync(
        [NotNull] KeyAndIV keyAndIV,
        [AllowNull] string cipherValue,
        CancellationToken cancellationToken = default
        )
    {
        Guard.Instance().ThrowIfNull(keyAndIV, nameof(keyAndIV))
            .ThrowIfFalse(keyAndIV.Key.LongLength == 32, nameof(keyAndIV))
            .ThrowIfFalse(keyAndIV.IV.LongLength == 16, nameof(keyAndIV));

        try
        {
            if (cipherValue is null || cipherValue.Length == 0)
            {
                logger.LogDebug(
                    "The '{t1}' service is returning an empty string because " +
                    "the incoming string was empty.",
                    nameof(CryptoService)
                    );
                return Task.FromResult(string.Empty)    ;
            }

            logger.LogDebug(
                "The '{t1}' service is generating an AES algorithm instance",
                nameof(CryptoService)
                );

            using var alg = Aes.Create();

            logger.LogDebug(
                "The '{t1}' service is setting the key and block sizes for AES",
                nameof(CryptoService)
                );

            alg.KeySize = 256;
            alg.BlockSize = 128;

            logger.LogDebug(
                "The '{t1}' service is setting the key and IV values for AES",
                nameof(CryptoService)
                );

            alg.Key = keyAndIV.Key;
            alg.IV = keyAndIV.IV;

            logger.LogDebug(
                "The '{t1}' service is converting '{t2}' encrypted characters " +
                "from base64",
                nameof(CryptoService),
                cipherValue.Length
                );

            var cipherBytes = Convert.FromBase64String(
                cipherValue
                );

            logger.LogDebug(
                "The '{t1}' service is creating a decryptor",
                nameof(CryptoService)
                );

            using var decryptor = alg.CreateDecryptor();

            logger.LogDebug(
                "The '{t1}' service is decrypting '{t2}' bytes",
                nameof(CryptoService),
                cipherBytes.Length
                );

            var plainBytes = decryptor.TransformFinalBlock(
                cipherBytes,
                0,
                cipherBytes.Length
                );

            logger.LogDebug(
                "The '{t1}' service is converting '{t2}' bytes to a string",
                nameof(CryptoService),
                plainBytes.Length
                );

            var plainText = UTF8Encoding.UTF8.GetString(
                plainBytes
                );

            logger.LogDebug(
                "The '{t1}' service is returning '{t2}' decrypted characters",
                nameof(CryptoService),
                plainText.Length
                );

            return Task.FromResult(plainText);
        }
        catch (Exception ex)
        {
            logger.LogError(
                ex,
                "The '{t1}' service failed to decrypt a string value!",
                nameof(CryptoService)
                );

            throw new ServiceException(
                innerException: ex,
                message: "Failed to decrypt a string value!"
                );
        }
    }

    #endregion

    // *******************************************************************
    // Stream methods.
    // *******************************************************************

    #region Stream methods

    /// <inheritdoc/>
    public async Task AesEncryptAsync(
        [NotNull] KeyAndIV keyAndIV,
        [NotNull] Stream plainStream,
        [NotNull] Stream cypherStream,
        CancellationToken cancellationToken = default
        )
    {
        Guard.Instance().ThrowIfNull(keyAndIV, nameof(keyAndIV))
            .ThrowIfFalse(keyAndIV.Key.LongLength == 32, nameof(keyAndIV))
            .ThrowIfFalse(keyAndIV.IV.LongLength == 16, nameof(keyAndIV))
            .ThrowIfNull(plainStream, nameof(plainStream))
            .ThrowIfNull(cypherStream, nameof(cypherStream));

        try
        {
            if (plainStream.Length == 0)
            {
                logger.LogDebug(
                    "The '{t1}' service is returning because the plain " +
                    "stream was empty.",
                    nameof(CryptoService)
                    );
                return;
            }

            logger.LogDebug(
                "The '{t1}' service is generating an AES algorithm instance",
                nameof(CryptoService)
                );

            using var alg = Aes.Create();

            logger.LogDebug(
                "The '{t1}' service is setting the key and block sizes for AES",
                nameof(CryptoService)
                );

            alg.KeySize = 256;
            alg.BlockSize = 128;

            logger.LogDebug(
                "The '{t1}' service is setting the key and IV values for AES",
                nameof(CryptoService)
                );

            alg.Key = keyAndIV.Key;
            alg.IV = keyAndIV.IV;

            logger.LogDebug(
                "The '{t1}' service is creating an encryptor",
                nameof(CryptoService)
                );

            using var encryptor = alg.CreateEncryptor();

            logger.LogDebug(
                "The '{t1}' service is creating a crypto stream",
                nameof(CryptoService)
                );

            using (var cryptoStream = new CryptoStream(
                        plainStream,
                        encryptor,
                        CryptoStreamMode.Read,
                        true
                        ))
            {
                logger.LogDebug(
                    "The '{t1}' service is copying bytes from the cryptography stream",
                    nameof(CryptoService)
                    );

                await cryptoStream.CopyToAsync(
                    cypherStream
                    ).ConfigureAwait(false);
            }

            logger.LogDebug(
                "The '{t1}' service is flushing the cypher stream",
                nameof(CryptoService)
                );

            await cypherStream.FlushAsync(
                cancellationToken
                ).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            logger.LogError(
                ex,
                "The '{t1}' service failed to encrypt a stream value!",
                nameof(CryptoService)
                );

            throw new ServiceException(
                innerException: ex,
                message: "Failed to encrypt a stream value!"
                );
        }
    }

    // *******************************************************************

    /// <inheritdoc/>
    public async Task AesDecryptAsync(
        [NotNull] KeyAndIV keyAndIV,
        [NotNull] Stream cypherStream,
        [NotNull] Stream plainStream,
        CancellationToken cancellationToken = default
        )
    {
        Guard.Instance().ThrowIfNull(keyAndIV, nameof(keyAndIV))
            .ThrowIfFalse(keyAndIV.Key.LongLength == 32, nameof(keyAndIV))
            .ThrowIfFalse(keyAndIV.IV.LongLength == 16, nameof(keyAndIV))
            .ThrowIfNull(cypherStream, nameof(cypherStream))
            .ThrowIfNull(plainStream, nameof(plainStream));

        try
        {
            if (cypherStream.Length == 0)
            {
                logger.LogDebug(
                    "The '{t1}' service is returning because the cypher " +
                    "stream was empty.",
                    nameof(CryptoService)
                    );
                return;
            }

            logger.LogDebug(
                "The '{t1}' service is generating an AES algorithm instance",
                nameof(CryptoService)
                );

            using var alg = Aes.Create();

            logger.LogDebug(
                "The '{t1}' service is setting the key and block sizes for AES",
                nameof(CryptoService)
                );

            alg.KeySize = 256;
            alg.BlockSize = 128;

            logger.LogDebug(
                "The '{t1}' service is setting the key and IV values for AES",
                nameof(CryptoService)
                );

            alg.Key = keyAndIV.Key;
            alg.IV = keyAndIV.IV;

            logger.LogDebug(
                "The '{t1}' service is creating an encryptor",
                nameof(CryptoService)
                );

            using var decryptor = alg.CreateDecryptor();

            logger.LogDebug(
                "The '{t1}' service is creating a crypto stream",
                nameof(CryptoService)
                );

            using (var cryptoStream = new CryptoStream(
                        plainStream,
                        decryptor,
                        CryptoStreamMode.Write,
                        true
                        ))
            {
                logger.LogDebug(
                    "The '{t1}' service is copying bytes from the cypher stream",
                    nameof(CryptoService)
                    );

                await cypherStream.CopyToAsync(
                    cryptoStream
                    ).ConfigureAwait(false);
            }

            logger.LogDebug(
                "The '{t1}' service is flushing the plain stream",
                nameof(CryptoService)
                );

            await plainStream.FlushAsync(
                cancellationToken
                ).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            logger.LogError(
                ex,
                "The '{t1}' service failed to decrypt a stream value!",
                nameof(CryptoService)
                );

            throw new ServiceException(
                innerException: ex,
                message: "Failed to decrypt a stream value!"
                );
        }
    }

    #endregion

}
