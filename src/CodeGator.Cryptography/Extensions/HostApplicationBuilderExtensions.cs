
#pragma warning disable IDE0130
namespace Microsoft.Extensions.Hosting;
#pragma warning restore IDE0130

/// <summary>
/// This class contains extension methods related to the <see cref="IHostApplicationBuilder"/>
/// type.
/// </summary>
public static partial class HostApplicationBuilderExtensions
{
    // *******************************************************************
    // Public methods.
    // *******************************************************************

    #region Public methods

    /// <summary>
    /// This method adds the types required to support the <c>CodeGator</c>
    /// <see cref="ICryptoService"/> type.
    /// </summary>
    /// <typeparam name="T">The type of application builder to use for the 
    /// operation.</typeparam>
    /// <param name="webApplicationBuilder">The web application builder to
    /// use for the operation.</param>
    /// <param name="bootstrapLogger">An optional bootstrap logger to use 
    /// for the operation.</param>
    /// <returns>The value of the <paramref name="webApplicationBuilder"/>
    /// parameter, for chaining calls together, Fluent style.</returns>
    /// <exception cref="ArgumentException">This exception is thrown whenever
    /// one or more arguments are missing, or invalid.</exception>
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

    #endregion
}
