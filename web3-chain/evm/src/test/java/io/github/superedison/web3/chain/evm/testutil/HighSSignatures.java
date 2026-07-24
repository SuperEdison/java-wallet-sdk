package io.github.superedison.web3.chain.evm.testutil;

import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.signer.SignatureScheme;
import io.github.superedison.web3.core.signer.SigningKey;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;

import java.math.BigInteger;
import java.util.Arrays;

/** Test-only helpers for constructing the malleable high-S form of a valid signature. */
public final class HighSSignatures {

    private static final BigInteger CURVE_ORDER =
            new BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);

    private HighSSignatures() {}

    public static byte[] fromCompact(byte[] lowSignature) {
        if (lowSignature.length != 65) {
            throw new IllegalArgumentException("Signature must be 65 bytes");
        }
        byte[] highSignature = Arrays.copyOf(lowSignature, lowSignature.length);
        byte[] highS = highS(Arrays.copyOfRange(lowSignature, 32, 64));
        System.arraycopy(highS, 0, highSignature, 32, 32);

        int v = lowSignature[64] & 0xff;
        if (v == 27 || v == 28) {
            highSignature[64] = (byte) (v == 27 ? 28 : 27);
        } else if (v >= 0 && v <= 3) {
            highSignature[64] = (byte) (v ^ 1);
        } else {
            throw new IllegalArgumentException("Unsupported recovery id: " + v);
        }
        return highSignature;
    }

    public static SigningKey wrapping(SigningKey delegate) {
        return new SigningKey() {
            @Override
            public Signature sign(byte[] hash) {
                Signature signature = delegate.sign(hash);
                if (!(signature instanceof Secp256k1Signer.Secp256k1Signature secp)) {
                    throw new IllegalStateException("Expected secp256k1 signature");
                }
                return new Secp256k1Signer.Secp256k1Signature(
                        secp.r(), highS(secp.s()), secp.v() ^ 1);
            }

            @Override
            public byte[] getPublicKey() {
                return delegate.getPublicKey();
            }

            @Override
            public SignatureScheme getScheme() {
                return delegate.getScheme();
            }

            @Override
            public void destroy() {
                delegate.destroy();
            }

            @Override
            public boolean isDestroyed() {
                return delegate.isDestroyed();
            }
        };
    }

    private static byte[] highS(byte[] lowS) {
        BigInteger highS = CURVE_ORDER.subtract(new BigInteger(1, lowS));
        byte[] encoded = highS.toByteArray();
        return Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
    }
}
