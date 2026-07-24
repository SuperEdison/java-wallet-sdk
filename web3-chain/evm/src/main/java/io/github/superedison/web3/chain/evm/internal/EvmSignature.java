package io.github.superedison.web3.chain.evm.internal;

import io.github.superedison.web3.chain.spi.signing.Secp256k1SignatureValidator;
import io.github.superedison.web3.chain.spi.signing.Secp256k1VNormalizer;
import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.signer.SignatureScheme;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * EVM 签名内部实现
 * r, s, v 只在 chain-evm 内部使用
 */
public final class EvmSignature implements Signature {

    private final byte[] r;
    private final byte[] s;
    private final long v;

    private EvmSignature(byte[] r, byte[] s, long v) {
        this.r = r;
        this.s = s;
        this.v = v;
    }

    /**
     * 从 recoveryId 创建 (recoveryId: 0/1 -> v: 27/28)
     */
    public static EvmSignature fromRecoveryId(byte[] r, byte[] s, int recoveryId) {
        if (recoveryId < 0 || recoveryId > 1) {
            throw new IllegalArgumentException("EVM compact signatures require recoveryId 0 or 1");
        }
        byte[] normalizedR = padTo32("r", r);
        byte[] normalizedS = padTo32("s", s);
        Secp256k1SignatureValidator.requireCanonical(normalizedR, normalizedS);
        return new EvmSignature(
                normalizedR, normalizedS, Secp256k1VNormalizer.toLegacyV(recoveryId));
    }

    /**
     * 从紧凑格式解析 (65 字节)
     */
    public static EvmSignature fromCompact(byte[] signature) {
        if (signature == null || signature.length != 65) {
            throw new IllegalArgumentException("Signature must be 65 bytes");
        }
        byte[] r = Arrays.copyOfRange(signature, 0, 32);
        byte[] s = Arrays.copyOfRange(signature, 32, 64);
        Secp256k1SignatureValidator.requireCanonical(r, s);
        long v = signature[64] & 0xFF;
        return new EvmSignature(r, s, v);
    }

    /** 解析 SigningKey 的内部输出；接受 recovery id，输出仍规范化为 legacy v。 */
    static EvmSignature fromSignerCompact(byte[] signature) {
        if (signature == null || signature.length != 65) {
            throw new IllegalArgumentException("Signature must be 65 bytes");
        }
        int rawV = signature[64] & 0xFF;
        int recoveryId;
        if (rawV <= 1) {
            recoveryId = rawV;
        } else if (rawV == 27 || rawV == 28) {
            recoveryId = rawV - 27;
        } else {
            throw new IllegalArgumentException("SigningKey signature v must be a recovery id");
        }
        return fromRecoveryId(
                Arrays.copyOfRange(signature, 0, 32),
                Arrays.copyOfRange(signature, 32, 64),
                recoveryId);
    }

    @Override
    public byte[] bytes() {
        byte[] result = new byte[65];
        System.arraycopy(r, 0, result, 0, 32);
        System.arraycopy(s, 0, result, 32, 32);
        result[64] = (byte) v;
        return result;
    }

    @Override
    public SignatureScheme scheme() {
        return SignatureScheme.ECDSA_SECP256K1;
    }

    public byte[] getR() {
        return Arrays.copyOf(r, 32);
    }

    public byte[] getS() {
        return Arrays.copyOf(s, 32);
    }

    public long getV() {
        return v;
    }

    public int getRecoveryId() {
        return Secp256k1VNormalizer.toRecoveryId(v);
    }

    public BigInteger getRBigInt() {
        return new BigInteger(1, r);
    }

    public BigInteger getSBigInt() {
        return new BigInteger(1, s);
    }

    /**
     * 转换为 EIP-155 签名
     */
    public EvmSignature toEip155(long chainId) {
        long newV = Secp256k1VNormalizer.toEip155V(v, chainId);
        return new EvmSignature(r, s, newV);
    }

    private static byte[] padTo32(String name, byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            throw new IllegalArgumentException(name + " must not be null or empty");
        }
        if (bytes.length == 32) return Arrays.copyOf(bytes, 32);
        if (bytes.length > 32) {
            for (int i = 0; i < bytes.length - 32; i++) {
                if (bytes[i] != 0) {
                    throw new IllegalArgumentException(name + " does not fit in 32 bytes");
                }
            }
            return Arrays.copyOfRange(bytes, bytes.length - 32, bytes.length);
        }
        byte[] padded = new byte[32];
        System.arraycopy(bytes, 0, padded, 32 - bytes.length, bytes.length);
        return padded;
    }
}
