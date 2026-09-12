using Veil.Crypto.Primitives;

namespace Veil.Crypto.Tests;

public class X25519Tests
{
    // RFC 7748 §6.1 test vectors.
    private const string AlicePrivate = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    private const string AlicePublic = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    private const string BobPrivate = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    private const string BobPublic = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    private const string Shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

    [Fact]
    public void DerivePublicKey_matches_rfc7748()
    {
        CryptoBytes.ToHex(X25519.DerivePublicKey(CryptoBytes.FromHex(AlicePrivate))).ShouldBe(AlicePublic);
        CryptoBytes.ToHex(X25519.DerivePublicKey(CryptoBytes.FromHex(BobPrivate))).ShouldBe(BobPublic);
    }

    [Fact]
    public void Agreement_matches_rfc7748_and_is_symmetric()
    {
        var ab = X25519.Agree(CryptoBytes.FromHex(AlicePrivate), CryptoBytes.FromHex(BobPublic));
        var ba = X25519.Agree(CryptoBytes.FromHex(BobPrivate), CryptoBytes.FromHex(AlicePublic));
        CryptoBytes.ToHex(ab).ShouldBe(Shared);
        ab.ShouldBe(ba);
    }

    [Fact]
    public void Agreement_rejects_low_order_point()
    {
        using var pair = X25519.GenerateKeyPair();
        Should.Throw<CryptoException>(() => X25519.Agree(pair.PrivateKey, new byte[32]));
    }

    [Fact]
    public void Dispose_zeroes_private_key()
    {
        var pair = X25519.GenerateKeyPair();
        pair.Dispose();
        pair.PrivateKey.ShouldAllBe(b => b == 0);
    }
}

public class Ed25519Tests
{
    // RFC 8032 §7.1 test 1 and test 2.
    [Theory]
    [InlineData(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")]
    [InlineData(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")]
    public void Sign_and_verify_match_rfc8032(string seedHex, string publicHex, string messageHex, string signatureHex)
    {
        var seed = CryptoBytes.FromHex(seedHex);
        var message = CryptoBytes.FromHex(messageHex);

        CryptoBytes.ToHex(Ed25519.DerivePublicKey(seed)).ShouldBe(publicHex);
        CryptoBytes.ToHex(Ed25519.Sign(seed, message)).ShouldBe(signatureHex);
        Ed25519.Verify(CryptoBytes.FromHex(publicHex), message, CryptoBytes.FromHex(signatureHex)).ShouldBeTrue();
    }

    [Fact]
    public void Verify_fails_on_modified_message_or_signature()
    {
        using var pair = Ed25519.GenerateKeyPair();
        var message = "hello"u8.ToArray();
        var signature = pair.Sign(message);

        Ed25519.Verify(pair.PublicKey, "hellp"u8, signature).ShouldBeFalse();
        signature[0] ^= 0x01;
        Ed25519.Verify(pair.PublicKey, message, signature).ShouldBeFalse();
        Ed25519.Verify(pair.PublicKey, message, new byte[10]).ShouldBeFalse();
    }
}

public class MlKem768Tests
{
    [Fact]
    public void Encapsulate_then_decapsulate_yields_same_secret()
    {
        using var pair = MlKem768.GenerateKeyPair();
        pair.PublicKey.Length.ShouldBe(ProtocolConstants.MlKem768PublicKeySize);
        pair.Seed.Length.ShouldBe(ProtocolConstants.MlKem768SeedSize);

        var (ciphertext, secret) = MlKem768.Encapsulate(pair.PublicKey);
        ciphertext.Length.ShouldBe(ProtocolConstants.MlKem768CiphertextSize);
        secret.Length.ShouldBe(ProtocolConstants.MlKem768SharedSecretSize);

        MlKem768.Decapsulate(pair.Seed, ciphertext).ShouldBe(secret);
    }

    [Fact]
    public void Public_key_is_deterministic_from_seed()
    {
        using var pair = MlKem768.GenerateKeyPair();
        MlKem768.DerivePublicKey(pair.Seed).ShouldBe(pair.PublicKey);
    }

    [Fact]
    public void Tampered_ciphertext_yields_different_secret_without_throwing()
    {
        using var pair = MlKem768.GenerateKeyPair();
        var (ciphertext, secret) = MlKem768.Encapsulate(pair.PublicKey);
        ciphertext[10] ^= 0xFF;

        // FIPS 203 implicit rejection: decapsulation returns a pseudo-random secret instead of failing loudly.
        MlKem768.Decapsulate(pair.Seed, ciphertext).ShouldNotBe(secret);
    }
}

public class KdfTests
{
    [Fact]
    public void Hkdf_matches_rfc5869_test_case_1()
    {
        var ikm = CryptoBytes.FromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        var salt = CryptoBytes.FromHex("000102030405060708090a0b0c");
        var info = CryptoBytes.FromHex("f0f1f2f3f4f5f6f7f8f9");

        var okm = Kdf.Hkdf(ikm, salt, info, 42);

        CryptoBytes.ToHex(okm).ShouldBe("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    }

    [Fact]
    public void Hmac_matches_rfc4231_test_case_2()
    {
        var mac = Kdf.Hmac("Jefe"u8, "what do ya want for nothing?"u8);
        CryptoBytes.ToHex(mac).ShouldBe("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }
}

public class AeadTests
{
    [Fact]
    public void Aes256Gcm_matches_known_answer()
    {
        // GCM spec test case 14: 256-bit zero key, zero IV, 16 zero bytes plaintext.
        var key = new byte[32];
        var nonce = new byte[12];
        var output = Aead.Encrypt(key, nonce, new byte[16], []);

        CryptoBytes.ToHex(output).ShouldBe("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919");
    }

    [Fact]
    public void Round_trip_with_associated_data()
    {
        var key = CryptoBytes.Random(32);
        var nonce = CryptoBytes.Random(12);
        var ciphertext = Aead.Encrypt(key, nonce, "secret"u8, "context"u8);

        Aead.Decrypt(key, nonce, ciphertext, "context"u8).ShouldBe("secret"u8.ToArray());
    }

    [Fact]
    public void Tampering_or_wrong_associated_data_fails()
    {
        var key = CryptoBytes.Random(32);
        var nonce = CryptoBytes.Random(12);
        var ciphertext = Aead.Encrypt(key, nonce, "secret"u8, "context"u8);

        Should.Throw<DecryptionFailedException>(() => Aead.Decrypt(key, nonce, ciphertext, "other"u8));

        ciphertext[0] ^= 0x01;
        Should.Throw<DecryptionFailedException>(() => Aead.Decrypt(key, nonce, ciphertext, "context"u8));
        Should.Throw<DecryptionFailedException>(() => Aead.Decrypt(key, nonce, new byte[5], "context"u8));
    }
}

public class PaddingTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(159)]
    [InlineData(160)]
    [InlineData(161)]
    [InlineData(4096)]
    public void Pad_produces_block_multiple_and_round_trips(int length)
    {
        var plaintext = CryptoBytes.Random(Math.Max(length, 1)).AsSpan(0, length).ToArray();

        var padded = Padding.Pad(plaintext);

        (padded.Length % ProtocolConstants.PaddingBlockSize).ShouldBe(0);
        padded.Length.ShouldBeGreaterThan(plaintext.Length);
        Padding.Unpad(padded).ShouldBe(plaintext);
    }

    [Fact]
    public void Unpad_rejects_missing_marker()
    {
        Should.Throw<MalformedMessageException>(() => Padding.Unpad(new byte[160]));
        Should.Throw<MalformedMessageException>(() => Padding.Unpad([]));
    }
}
