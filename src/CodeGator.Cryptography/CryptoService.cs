
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
    public Task<KeyAndIV> GenerateKeyAndIVAsync(
        [NotNull] string password,
        [NotNull] string salt,
        [NotNull] string hashAlgorithmName,
        int rfc2898Iterations,
        CancellationToken cancellationToken = default
        )
    {
        Guard.Instance().ThrowIfNullOrEmpty(password, nameof(password))
            .ThrowIfNullOrEmpty(salt, nameof(salt))
            .ThrowIfNullOrEmpty(hashAlgorithmName, nameof(hashAlgorithmName))
            .ThrowIfLessThan(rfc2898Iterations, 10000, nameof(rfc2898Iterations));

        try
        {
            logger.LogDebug(
                "The '{t1}' service is generating an AES algorithm instance",
                nameof(CryptoService)
                );

            var hashAlgorithm = new HashAlgorithmName(
                hashAlgorithmName
                );

            using var alg = Aes.Create();

            logger.LogDebug(
                "The '{t1}' service is setting the key and block sizes",
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
                "The '{t1}' service is deriving an RFC2898 based cryptographic key",
                nameof(CryptoService)
                );

            var derivedKey = new Rfc2898DeriveBytes(
                passwordBytes,
                saltBytes,
                rfc2898Iterations,
                hashAlgorithm
                );

            logger.LogDebug(
                "The '{t1}' service is packaging Key and IV",
                nameof(CryptoService)
                );

            var keyAndIV = new KeyAndIV()
            {
                Key = derivedKey.GetBytes(alg.KeySize / 8),
                IV = derivedKey.GetBytes(alg.BlockSize / 8)
            };

            return Task.FromResult(keyAndIV);
        }
        catch (Exception ex)
        {
            logger.LogError(
                ex,
                "the '{t1}' service failed to generate a cryptographic Key and IV!",
                nameof(CryptoService)
                );

            throw new ServiceException(
                message: $"Failed to generate a cryptographic Key and IV!",
                innerException: ex
                );
        }
    }

    // *******************************************************************

    /// <inheritdoc/>
    public Task<KeyAndIV> GenerateKeyAndIVAsync(
        [NotNull] string hashAlgorithmName = "SHA512",
        int rfc2898Iterations = 15000,
        CancellationToken cancellationToken = default
        )
    {
        Guard.Instance().ThrowIfNullOrEmpty(hashAlgorithmName, nameof(hashAlgorithmName))
            .ThrowIfLessThan(rfc2898Iterations, 10000, nameof(rfc2898Iterations));

        try
        {
            logger.LogDebug(
                "The '{t1}' service is generating an AES algorithm instance",
                nameof(CryptoService)
                );

            var hashAlgorithm = new HashAlgorithmName(
                hashAlgorithmName
                );

            using var alg = Aes.Create();

            logger.LogDebug(
                "The '{t1}' service is setting the key and block sizes",
                nameof(CryptoService)
                );

            alg.KeySize = 256;
            alg.BlockSize = 128;

            logger.LogDebug(
                "The '{t1}' service is generating a random password",
                nameof(CryptoService)
                );

            var passwordBytes = new byte[alg.KeySize];
            randomNumberGenerator.GetNonZeroBytes(passwordBytes);

            logger.LogDebug(
                "The '{t1}' service is generating a random SALT",
                nameof(CryptoService)
                );

            var saltBytes = new byte[alg.BlockSize];
            randomNumberGenerator.GetNonZeroBytes(saltBytes);

            logger.LogDebug(
                "The '{t1}' service is deriving an RFC2898 based cryptographic key",
                nameof(CryptoService)
                );

            var derivedKey = new Rfc2898DeriveBytes(
                passwordBytes,
                saltBytes,
                rfc2898Iterations,
                hashAlgorithm
                );

            logger.LogDebug(
                "The '{t1}' service is packaging Key and IV",
                nameof(CryptoService)
                );

            var keyAndIV = new KeyAndIV()
            {
                Key = derivedKey.GetBytes(alg.KeySize / 8),
                IV = derivedKey.GetBytes(alg.BlockSize / 8)
            };

            return Task.FromResult(keyAndIV);
        }
        catch (Exception ex)
        {
            logger.LogError(
                ex,
                "the '{t1}' service failed to generate a random cryptographic Key and IV!",
                nameof(CryptoService)
                );

            throw new ServiceException(
                message: $"Failed to generate a random cryptographic Key and IV!",
                innerException: ex
                );
        }
    }

    #endregion

    // *******************************************************************
    // AES encrypt byte methods.
    // *******************************************************************

    #region AES encrypt byte methods

    /// <inheritdoc/>
    public async Task<byte[]> AesEncryptAsync(
        [NotNull] byte[] key,
        [NotNull] byte[] iv,
        [AllowNull] byte[] value,
        CancellationToken cancellationToken = default
        )
    {
        Guard.Instance().ThrowIfNull(key, nameof(key))
            .ThrowIfNull(iv, nameof(iv))
            .ThrowIfFalse(key.LongLength == 32, nameof(key))
            .ThrowIfFalse(iv.LongLength == 16, nameof(iv));

        try
        {
            if (value is null || value.Length == 0)
            {
                return [];
            }

            logger.LogDebug(
                "The '{t1}' service is generating an AES algorithm instance",
                nameof(CryptoService)
                );

            using var alg = Aes.Create();
            
            logger.LogDebug(
                "The '{t1}' service is configuring an AES algorithm instance",
                nameof(CryptoService)
                );

            alg.Mode = CipherMode.CBC;
            alg.KeySize = 256;
            alg.BlockSize = 128;
            alg.FeedbackSize = 128;
            alg.Padding = PaddingMode.PKCS7;
            alg.Key = key;
            alg.IV = iv;

            logger.LogDebug(
                "The '{t1}' service is creating an encryptor",
                nameof(CryptoService)
                );

            using var enc = alg.CreateEncryptor();
            
            logger.LogDebug(
                "The '{t1}' service is creating a memory stream",
                nameof(CryptoService)
                );

            using var memStream = new MemoryStream();
            
            logger.LogDebug(
                "The '{t1}' service is creating a crypto stream",
                nameof(CryptoService)
                );

            using var cryptoStream = new CryptoStream(
                memStream,
                enc,
                CryptoStreamMode.Write
                );

            logger.LogDebug(
                "The '{t1}' service is writing plain bytes",
                nameof(CryptoService)
                );

            await cryptoStream.WriteAsync(
                value,
                cancellationToken
                ).ConfigureAwait(false);

            await cryptoStream.FlushFinalBlockAsync(
                cancellationToken
                ).ConfigureAwait(false);

            logger.LogDebug(
                "The '{t1}' service is reading the encrypted bytes",
                nameof(CryptoService)
                );

            var encrypted = memStream.ToArray();
            return encrypted;
        }
        catch (Exception ex)
        {
            logger.LogError(
                ex,
                "The '{t1}' service failed to AES encrypt bytes",
                nameof(CryptoService)
            );

            throw new ServiceException(
                innerException: ex,
                message: $"Failed to AES encrypt bytes!"
                );
        }
    }

    #endregion

    // *******************************************************************
    // AES decrypt byte methods.
    // *******************************************************************

    #region AES decrypt byte methods

    /// <inheritdoc/>
    public async Task<byte[]> AesDecryptAsync(
        [NotNull] byte[] key,
        [NotNull] byte[] iv,
        [AllowNull] byte[] value,
        CancellationToken cancellationToken = default
        )
    {
        Guard.Instance().ThrowIfNull(key, nameof(key))
           .ThrowIfNull(iv, nameof(iv))
           .ThrowIfFalse(key.LongLength == 32, nameof(key))
           .ThrowIfFalse(iv.LongLength == 16, nameof(iv));

        try
        {
            if (value is null || value.Length == 0)
            {
                return [];
            }

            logger.LogDebug(
                "The '{t1}' service is generating an AES algorithm instance",
                nameof(CryptoService)
                );

            using var alg = Aes.Create();
            
            logger.LogDebug(
                "The '{t1}' service is configuring an AES algorithm instance",
                nameof(CryptoService)
                );

            alg.Mode = CipherMode.CBC;
            alg.KeySize = 256;
            alg.BlockSize = 128;
            alg.FeedbackSize = 128;
            alg.Padding = PaddingMode.PKCS7;

            logger.LogDebug(
                "The '{t1}' service is setting the key and IV values",
                nameof(CryptoService)
                );

            alg.Key = key;
            alg.IV = iv;

            logger.LogDebug(
                "The '{t1}' service is creating a decryptor",
                nameof(CryptoService)
                );

            using var dec = alg.CreateDecryptor();
                
            logger.LogDebug(
                "The '{t1}' service is creating a memory stream",
                nameof(CryptoService)
                );

            using var memStream = new MemoryStream();
                    
            logger.LogDebug(
                "The '{t1}' service is creating a crypto stream",
                nameof(CryptoService)
                );

            using var cryptoStream = new CryptoStream(
                memStream,
                dec,
                CryptoStreamMode.Write
                );
                        
            logger.LogDebug(
                "The '{t1}' service is writing encrypted bytes",
                nameof(CryptoService)
                );

            await cryptoStream.WriteAsync(
                value,
                0,
                value.Length,
                cancellationToken
                ).ConfigureAwait(false);

            await cryptoStream.FlushFinalBlockAsync(
                cancellationToken
                ).ConfigureAwait(false);
                        
            logger.LogDebug(
                "The '{t1}' service is reading the decrypted bytes",
                nameof(CryptoService)
                );

            var decrypted = memStream.ToArray();
            return decrypted;            
        }
        catch (Exception ex)
        {
            logger.LogError(
                ex,
                "The '{t1}' service failed to AES decrypt bytes",
                nameof(CryptoService)
            );

            throw new ServiceException(
                innerException: ex,
                message: $"Failed to AES decrypt bytes!"
                );
        }
    }
        
    // *******************************************************************

    /// <inheritdoc/>
    public async Task<byte[]> AesDecryptAsync(
        [NotNull] KeyAndIV keyAndIV,
        [AllowNull] byte[] value,
        CancellationToken cancellationToken = default
        )
    {
        return await AesDecryptAsync(
            keyAndIV.Key,
            keyAndIV.IV,
            value,
            cancellationToken
            ).ConfigureAwait(false);
    }

    #endregion

    // *******************************************************************
    // AES encrypt string methods.
    // *******************************************************************

    #region AES encrypt string methods

    /// <inheritdoc/>
    public async Task<string> AesEncryptAsync(
        [NotNull] byte[] key,
        [NotNull] byte[] iv,
        [AllowNull] string? value,
        CancellationToken cancellationToken = default
        )
    {
        Guard.Instance().ThrowIfNull(key, nameof(key))
            .ThrowIfNull(iv, nameof(iv))
            .ThrowIfFalse(key.LongLength == 32, nameof(key))
            .ThrowIfFalse(iv.LongLength == 16, nameof(iv));

        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        logger.LogDebug(
            "The '{t1}' service is generating an AES algorithm instance",
            nameof(CryptoService)
            );

        using var alg = Aes.Create();

        logger.LogDebug(
            "The '{t1}' service is configuring an AES algorithm instance",
            nameof(CryptoService)
            );

        alg.Mode = CipherMode.CBC;
        alg.KeySize = 256;
        alg.BlockSize = 128;
        alg.FeedbackSize = 128;
        alg.Padding = PaddingMode.PKCS7;
        alg.Key = key;
        alg.IV = iv;

        logger.LogDebug(
            "The '{t1}' service is creating an encryptor",
            nameof(CryptoService)
            );

        using var enc = alg.CreateEncryptor();

        logger.LogDebug(
            "The '{t1}' service is creating a memory stream",
            nameof(CryptoService)
            );

        using var memStream = new MemoryStream();

        logger.LogDebug(
            "The '{t1}' service is creating a crypto stream",
            nameof(CryptoService)
            );

        using var cryptoStream = new CryptoStream(
            memStream,
            enc,
            CryptoStreamMode.Write
            );

        logger.LogDebug(
            "The '{t1}' service is creating a stream writer",
            nameof(CryptoService)
            );

        // Do NOT remove this using block!
        using (var writer = new StreamWriter(cryptoStream))
        {
            logger.LogDebug(
                "The '{t1}' service is writing plain bytes",
                nameof(CryptoService)
                );

            await writer.WriteAsync(
                value
                ).ConfigureAwait(false);
        }

        logger.LogDebug(
            "The '{t1}' service is reading the encrypted bytes",
            nameof(CryptoService)
            );

        var encryptedBytes = memStream.ToArray();

        logger.LogDebug(
            "The '{t1}' service is converting bytes to a Base64 string",
            nameof(CryptoService)
            );

        var encryptedValue = Convert.ToBase64String(
            encryptedBytes
            );

        return encryptedValue;
    }

    // *******************************************************************

    /// <inheritdoc/>
    public async Task<string> AesEncryptAsync(
        [NotNull] KeyAndIV keyAndIV,
        [AllowNull] string? value,
        CancellationToken cancellationToken = default
        )
    {
        return await AesEncryptAsync(
            keyAndIV.Key,
            keyAndIV.IV,
            value,
            cancellationToken
            ).ConfigureAwait(false);
    }

    // *******************************************************************

    /// <inheritdoc/>
    public async Task<byte[]> AesEncryptAsync(
        [NotNull] KeyAndIV keyAndIV,
        [AllowNull] byte[] value,
        CancellationToken cancellationToken = default
        )
    {
        return await AesEncryptAsync(
            keyAndIV.Key,
            keyAndIV.IV,
            value,
            cancellationToken
            ).ConfigureAwait(false);
    }
        
    #endregion

    // *******************************************************************
    // AES decrypt string methods.
    // *******************************************************************

    #region AES decrypt string methods

    /// <inheritdoc/>
    public Task<string> AesDecryptAsync(
        [NotNull] byte[] key,
        [NotNull] byte[] iv,
        [AllowNull] string? value,
        CancellationToken cancellationToken = default
        )
    {
        Guard.Instance().ThrowIfNull(key, nameof(key))
            .ThrowIfNull(iv, nameof(iv))
            .ThrowIfFalse(key.LongLength == 32, nameof(key))
            .ThrowIfFalse(iv.LongLength == 16, nameof(iv));

        if (string.IsNullOrEmpty(value))
        {
            return Task.FromResult(string.Empty);
        }

        logger.LogDebug(
            "The '{t1}' service is generating an AES algorithm instance",
            nameof(CryptoService)
            );

        using var alg = Aes.Create();

        logger.LogDebug(
            "The '{t1}' service is configuring an AES algorithm instance",
            nameof(CryptoService)
            );

        alg.Mode = CipherMode.CBC;
        alg.KeySize = 256;
        alg.BlockSize = 128;
        alg.FeedbackSize = 128;
        alg.Padding = PaddingMode.PKCS7;

        alg.Key = key;
        alg.IV = iv;

        logger.LogDebug(
            "The '{t1}' service is creating an encryptor",
            nameof(CryptoService)
            );

        using var dec = alg.CreateDecryptor();

        var encryptedBytes = Convert.FromBase64String(value);

        logger.LogDebug(
            "The '{t1}' service is creating a memory stream",
            nameof(CryptoService)
            );

        using var memStream = new MemoryStream(encryptedBytes);

        logger.LogDebug(
            "The '{t1}' service is creating a crypto stream",
            nameof(CryptoService)
            );

        using var cryptoStream = new CryptoStream(
            memStream,
            dec,
            CryptoStreamMode.Read
            );

        logger.LogDebug(
            "The '{t1}' service is creating a stream reader",
            nameof(CryptoService)
            );

        // Do NOT delete this using block!
        using (var reader = new StreamReader(cryptoStream))
        {
            logger.LogDebug(
                "The '{t1}' service is writing plain text",
                nameof(CryptoService)
                );

            var plainText = reader.ReadToEnd();

            return Task.FromResult(plainText);
        }
    }

    // *******************************************************************

    /// <inheritdoc/>
    public async Task<string> AesDecryptAsync(
        [NotNull] KeyAndIV keyAndIV,
        [AllowNull] string? value,
        CancellationToken cancellationToken = default
        )
    {
        return await AesDecryptAsync(
            keyAndIV.Key,
            keyAndIV.IV,
            value,
            cancellationToken
            ).ConfigureAwait(false);
    }

    #endregion
}
