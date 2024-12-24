
namespace CodeGator.Cryptography;

/// <summary>
/// This class represents a cryptographic key and initialization vector.
/// </summary>
public class KeyAndIV
{
    // *******************************************************************
    // Properties.
    // *******************************************************************

    #region Properties

    /// <summary>
    /// This property contains a cryptographic key.
    /// </summary>
    [Required]
    public byte[] Key { get; set; } = null!;

    /// <summary>
    /// This property contains a cryptographic initialization vector.
    /// </summary>
    [Required]
    public byte[] IV { get; set; } = null!;

    #endregion
}
