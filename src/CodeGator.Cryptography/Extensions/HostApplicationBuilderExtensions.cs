
#pragma warning disable IDE0130
namespace Microsoft.Extensions.Hosting;
#pragma warning restore IDE0130

/// <summary>
/// This class contains extension methods for <see cref="IHostApplicationBuilder"/>.
/// </summary>
public static partial class HostApplicationBuilderExtensions
{

    /// <summary>
    /// This method registers CodeGator cryptography services on the builder.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Registers <see cref="ICryptoService"/> as <see cref="CryptoService"/> and a
    /// singleton <see cref="RandomNumberGenerator"/> for cryptographic operations.
    /// </para>
    /// </remarks>
    /// <typeparam name="T">The application builder type.</typeparam>
    /// <param name="webApplicationBuilder">The host application builder.</param>
    /// <param name="bootstrapLogger">Optional logger for registration diagnostics.</param>
    /// <returns><paramref name="webApplicationBuilder"/> for fluent chaining.</returns>
    /// <exception cref="ArgumentNullException">This exception is thrown when
    /// <paramref name="webApplicationBuilder"/> is <see langword="null"/>.</exception>
    public static T AddCodeGatorCryptography<T>(
        [NotNull] this T webApplicationBuilder,
        [AllowNull] ILogger? bootstrapLogger = null
        ) where T : IHostApplicationBuilder
    {
        Guard.Instance().ThrowIfNull(webApplicationBuilder, nameof(webApplicationBuilder));

        bootstrapLogger?.LogDebug(
            "Registering the CodeGator crypto services."
            );
                
        webApplicationBuilder.Services.AddSingleton<ICryptoService, CryptoService>();

        bootstrapLogger?.LogDebug(
            "Registering the random number generator."
            );

        webApplicationBuilder.Services.AddSingleton<RandomNumberGenerator>(serviceProvider =>
        {
            return RandomNumberGenerator.Create();
        });

        return webApplicationBuilder;
    }

}
