# Veil protocol

This document specifies exactly what `Veil.Crypto` implements. It follows the published Signal specifications
for [PQXDH](https://signal.org/docs/specifications/pqxdh/) and the
[Double Ratchet](https://signal.org/docs/specifications/doubleratchet/) with the concrete parameter choices
below. Everything is versioned (`ProtocolConstants.Version = 1`); every KDF info string and every signed
structure carries a `Veil_*_v1` label so values from one context can never be confused with another.

## Primitives

| Purpose | Algorithm | Implementation |
|---|---|---|
| Diffie–Hellman | X25519 (RFC 7748), low-order points rejected | BouncyCastle |
| Signatures | Ed25519 (RFC 8032, pure) | BouncyCastle |
| KEM | ML-KEM-768 (FIPS 203) | BouncyCastle |
| KDF | HKDF-SHA256 (RFC 5869) | .NET `HKDF` |
| MAC | HMAC-SHA256 | .NET |
| AEAD | AES-256-GCM, 96-bit nonce, 128-bit tag | .NET `AesGcm` |
| Passphrase KDF (client state) | Argon2id 64 MiB / 3 / 4 | BouncyCastle |

## Keys

Each device owns:

- **Identity**: an Ed25519 signing key `SIK` and an X25519 DH key `IK`. `IK` is bound to `SIK` by
  `Sig(SIK, 0x01 ‖ "Veil_IdentityDhKey_v1" ‖ 0x00000000 ‖ IK)`.
- **Signed pre-key** `SPK` (X25519, rotated periodically) with `Sig(SIK, 0x01 ‖ "Veil_SignedPreKey_v1" ‖ id ‖ SPK)`.
- **KEM pre-key** `PQPK` (ML-KEM-768 public key, 1184 bytes) with `Sig(SIK, 0x01 ‖ "Veil_KemPreKey_v1" ‖ id ‖ PQPK)`.
- **One-time pre-keys** `OPK_i` (X25519), uploaded in batches, each consumed by at most one handshake.

The server stores the public halves only. A **pre-key bundle** served to an initiator is
`{SIK, IK, IK-signature, SPK id/key/signature, PQPK id/key/signature, optional OPK id/key}`; the initiator verifies
all three signatures before using it (`PreKeyBundle.Verify`).

## PQXDH handshake

Alice (initiator) with identity `(SIK_A, IK_A)`, Bob (responder) with bundle as above.

1. Verify the bundle. Generate ephemeral `EK_A`.
2. `(CT, SS) = ML-KEM-768.Encaps(PQPK_B)`.
3. `DH1 = DH(IK_A, SPK_B)`, `DH2 = DH(EK_A, IK_B)`, `DH3 = DH(EK_A, SPK_B)`, `DH4 = DH(EK_A, OPK_B)` if an OPK was included.
4. `SK = HKDF-SHA256(salt = 0³², ikm = 0xFF³² ‖ DH1 ‖ DH2 ‖ DH3 ‖ [DH4] ‖ SS, info = "Veil_PQXDH_v1_X25519_MLKEM768_SHA256", 32)`.
5. `AD = SIK_A ‖ IK_A ‖ SIK_B ‖ IK_B` (128 bytes) — associated data for every ratchet message of the session.
6. Alice initialises the Double Ratchet as initiator with `SK` and `SPK_B` as Bob's first ratchet key, and attaches a **pre-key header** to every message until Bob replies:

```
PreKeyHeader = SIK_A(32) ‖ IK_A(32) ‖ IK_A-signature(64) ‖ EK_A(32) ‖ spkId(4) ‖ hasOpk(1) ‖ opkId(4) ‖ pqpkId(4) ‖ CT(1088)
```

Bob reconstructs `SK` with his private `IK_B`, `SPK_B`, `PQPK_B` (decapsulating `CT`) and the consumed `OPK_B`,
then initialises the ratchet as responder with the `SPK_B` key pair. A second use of the same `OPK` id fails
(`SessionException`), which also defeats replay of the handshake.

Security properties: mutual authentication through `DH1`/`DH2`, forward secrecy through `EK_A` and `OPK_B`,
and post-quantum confidentiality because `SS` is mixed into `SK` — an attacker who records traffic today and
later breaks X25519 still needs to break ML-KEM-768.

## Double Ratchet

State: own ratchet key pair `DHs`, remote ratchet key `DHr`, root key `RK`, sending/receiving chain keys
`CKs`/`CKr`, counters `Ns`, `Nr`, `PN`, and a bounded map of skipped message keys.

- Root KDF: `HKDF-SHA256(salt = RK, ikm = DH(DHs, DHr), info = "Veil_DoubleRatchet_RootKDF_v1", 64) → (RK', CK)`.
- Chain KDF: `MK = HMAC(CK, 0x01)`, `CK' = HMAC(CK, 0x02)`.
- Message keys: `HKDF-SHA256(salt = 0³², ikm = MK, info = "Veil_DoubleRatchet_MessageKeys_v1", 44) → (AES key 32, nonce 12)`.
- Header: `DHs.pub(32) ‖ PN(4, big-endian) ‖ N(4)`; AEAD associated data is `AD ‖ header`.
- Up to 1000 message keys may be skipped ahead for out-of-order delivery; at most 2000 are retained (FIFO eviction).
- Decryption works on a **copy** of the state and commits only after the tag verifies, so a forged or corrupted
  message cannot advance or corrupt the session. Replays fail because the message key has been deleted.
- The responder cannot send until it has received the first message (per the specification); in practice it
  always has, because its session is created *from* that message.

## Plaintext and padding

The application plaintext is a UTF-8 JSON `ChatMessage { type, conversationId, body, sentAt }`. Binding the
conversation id inside the ciphertext lets the recipient detect a server that re-routes an envelope to a
different conversation. Before encryption the plaintext is padded (ISO/IEC 7816-4: `0x80` then zeros) to a
multiple of 160 bytes, so ciphertext lengths reveal only a coarse size bucket.

## Envelope (what the server stores)

```
version(1) = 0x01 ‖ type(1) ‖ [PreKeyHeader if type = 0x01] ‖ RatchetHeader(40) ‖ AES-GCM ciphertext ‖ tag(16)
```

`type` is `0x01` (pre-key message) or `0x02` (message). The server never parses beyond the length limit
(64 KiB). One envelope is produced per recipient **device**; the server verifies that the sender addressed
every active device of every member (except its own current device) and otherwise returns `409` with the
missing/stale device ids so the client can repair its session table and re-encrypt.

## Safety numbers

For each side, `fp = SHA-512^5200("Veil_SafetyNumber_v1" ‖ SIK ‖ IK ‖ NFKC(username))` iterated with the key
material re-appended each round; the first 30 bytes become six 5-digit groups. The safety number is the
lexicographic concatenation of both fingerprints (60 digits). Both users see the same string; comparing it
over a trusted channel rules out key substitution by anyone, the server included. The SDK additionally pins
the identity fingerprint of every peer device (trust on first use) and raises `IdentityChanged` when it changes.

## Client state at rest

`ClientState` (device keys, ratchet sessions, pins, refresh token) is serialised to JSON and stored as
`"VEIL" ‖ 0x01 ‖ salt(16) ‖ nonce(12) ‖ AES-256-GCM(key = Argon2id(passphrase, salt), aad = "Veil_ClientState_v1")`.
A wrong passphrase is indistinguishable from a corrupted file.

## Known limitations

- Pairwise fan-out: group messages are encrypted once per recipient device (Sender Keys are on the roadmap).
- No header encryption: ratchet public keys and counters are visible to the server (as in Signal's baseline).
- No one-time PQ pre-keys yet: the KEM pre-key is a rotating "last-resort" key, so post-quantum forward secrecy
  of the handshake is bounded by its rotation period (classical forward secrecy is per message).
- Sealed sender is not implemented; the server learns sender/recipient device pairs (needed for routing).
