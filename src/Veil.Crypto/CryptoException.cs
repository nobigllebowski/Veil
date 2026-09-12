namespace Veil.Crypto;

/// <summary>Base exception for every failure raised by the Veil protocol library.</summary>
public class CryptoException : Exception
{
    public CryptoException() { }
    public CryptoException(string message) : base(message) { }
    public CryptoException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>Raised when a signature over pre-key material does not verify. Treat as a possible MITM attempt.</summary>
public sealed class InvalidSignatureException : CryptoException
{
    public InvalidSignatureException() : base("Signature verification failed.") { }
    public InvalidSignatureException(string message) : base(message) { }
    public InvalidSignatureException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>Raised when authenticated decryption fails (wrong key, tampered ciphertext, or replay).</summary>
public sealed class DecryptionFailedException : CryptoException
{
    public DecryptionFailedException() : base("Authenticated decryption failed.") { }
    public DecryptionFailedException(string message) : base(message) { }
    public DecryptionFailedException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>Raised when a message cannot be processed by the current session state (e.g. too many skipped keys).</summary>
public sealed class SessionException : CryptoException
{
    public SessionException() { }
    public SessionException(string message) : base(message) { }
    public SessionException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>Raised when wire data is malformed.</summary>
public sealed class MalformedMessageException : CryptoException
{
    public MalformedMessageException() : base("Malformed protocol message.") { }
    public MalformedMessageException(string message) : base(message) { }
    public MalformedMessageException(string message, Exception innerException) : base(message, innerException) { }
}
