using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace CodeGator.Cryptography;

/// <summary>
/// Unit tests for <see cref="HostApplicationBuilderExtensions"/>.
/// </summary>
[TestClass]
public sealed class HostApplicationBuilderExtensionsTests
{
    [TestCategory("Unit")]
    [TestMethod]
    public async Task AddCodeGatorCryptography_RegistersCryptoServiceAndRandomNumberGenerator()
    {
        var builder = Host.CreateApplicationBuilder(
            new HostApplicationBuilderSettings { DisableDefaults = true }
            );

        builder.AddCodeGatorCryptography();

        await using var provider = builder.Services.BuildServiceProvider();
        var crypto = provider.GetRequiredService<ICryptoService>();
        var rng = provider.GetRequiredService<RandomNumberGenerator>();

        Assert.IsInstanceOfType<CryptoService>(crypto);
        Assert.IsNotNull(rng);
    }

    [TestCategory("Unit")]
    [TestMethod]
    public async Task AddCodeGatorCryptography_ResolvedService_GeneratesKeyAndIV()
    {
        var builder = Host.CreateApplicationBuilder(
            new HostApplicationBuilderSettings { DisableDefaults = true }
            );

        builder.AddCodeGatorCryptography();

        await using var provider = builder.Services.BuildServiceProvider();
        var crypto = provider.GetRequiredService<ICryptoService>();

        var keyAndIV = await crypto.GenerateKeyAndIVAsync();

        Assert.AreEqual(32, keyAndIV.Key.Length);
        Assert.AreEqual(16, keyAndIV.IV.Length);
    }
}
