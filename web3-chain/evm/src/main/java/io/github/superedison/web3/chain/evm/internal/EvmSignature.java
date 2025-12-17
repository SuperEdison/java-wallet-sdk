package io.github.superedison.web3.chain.evm.internal;

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
    private final int v;

    private EvmSignature(byte[] r, byte[] s, int v) {
        this.r = r;
        this.s = s;
        this.v = v;
    }

    /**
     * 从 recoveryId 创建 (recoveryId: 0/1 -> v: 27/28)
     */
    public static EvmSignature fromRecoveryId(byte[] r, byte[] s, int recoveryId) {
        return new EvmSignature(padTo32(r), padTo32(s), recoveryId + 27);
    }

    /**
     * 从紧凑格式解析 (65 字节)
     */
    public static EvmSignature fromCompact(byte[] signature) {
        if (signature.length != 65) {
            throw new IllegalArgumentException("Signature must be 65 bytes");
        }
        byte[] r = Arrays.copyOfRange(signature, 0, 32);
        byte[] s = Arrays.copyOfRange(signature, 32, 64);
        int v = signature[64] & 0xFF;
        return new EvmSignature(r, s, v);
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

    public int getV() {
        return v;
    }

    public int getRecoveryId() {
        if (v >= 35) {
            return (v - 35) % 2;
        }
        return v - 27;
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
        int newV = (int) (chainId * 2 + 35 + getRecoveryId());
        return new EvmSignature(r, s, newV);
    }

    private static byte[] padTo32(byte[] bytes) {
        if (bytes.length == 32) return Arrays.copyOf(bytes, 32);
        if (bytes.length > 32) {
            return Arrays.copyOfRange(bytes, bytes.length - 32, bytes.length);
        }
        byte[] padded = new byte[32];
        System.arraycopy(bytes, 0, padded, 32 - bytes.length, bytes.length);
        return padded;
    }
}