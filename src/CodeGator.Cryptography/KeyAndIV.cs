
namespace CodeGator.Cryptography;

/// <summary>
/// This class represents a cryptographic key and initialization vector.
/// </summary>
public class KeyAndIV
{

    /// <summary>
    /// This property holds the AES key bytes for operations on this service.
    /// </summary>
    [Required]
    public byte[] Key { get; set; } = null!;

    /// <summary>
    /// This property holds the AES IV for operations on this service.
    /// </summary>
    /// <remarks>
    /// <para>Stores the 128-bit block initialization vector used with the key.</para>
    /// </remarks>
    [Required]
    public byte[] IV { get; set; } = null!;

}
