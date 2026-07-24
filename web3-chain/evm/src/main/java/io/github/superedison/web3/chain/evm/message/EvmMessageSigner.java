package io.github.superedison.web3.chain.evm.message;

import io.github.superedison.web3.chain.evm.address.EvmAddress;
import io.github.superedison.web3.chain.evm.internal.EvmSignature;
import io.github.superedison.web3.chain.spi.signing.Secp256k1SignatureValidator;
import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.signer.SigningKey;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;

/**
 * EVM 消息签名器（EIP-191 personal_sign）。
 *
 * 不再接收 {@code byte[] privateKey}——私钥是"能力"不是"数据"，统一通过 {@link SigningKey}
 * 抽象，所以本地 secp256k1 私钥、AWS KMS、HSM、硬件钱包都能复用同一套入口。
 *
 * <pre>{@code
 * // 本地签名
 * try (SigningKey key = new Secp256k1Signer(privateKey)) {
 *     Signature sig = EvmMessageSigner.signMessage("hello", key);
 * }
 *
 * // KMS 托管
 * try (SigningKey key = new AwsKmsSecp256k1Key(kms, "alias/eth-hot")) {
 *     Signature sig = EvmMessageSigner.signMessage("hello", key);
 * }
 * }</pre>
 */
public final class EvmMessageSigner {

    private EvmMessageSigner() {}

    /** 签名原始字节消息（EIP-191）。 */
    public static Signature signMessage(byte[] message, SigningKey signingKey) {
        return signHash(Eip191Prefix.hash(message), signingKey);
    }

    /** 签名字符串消息（EIP-191）。 */
    public static Signature signMessage(String message, SigningKey signingKey) {
        return signHash(Eip191Prefix.hash(message), signingKey);
    }

    /** 直接签 32 字节哈希。 */
    public static Signature signHash(byte[] hash, SigningKey signingKey) {
        var result = (Secp256k1Signer.Secp256k1Signature) signingKey.sign(hash);
        return EvmSignature.fromRecoveryId(result.r(), result.s(), result.v());
    }

    /** 验证消息签名。 */
    public static boolean verifyMessage(byte[] message, Signature signature, byte[] publicKey) {
        return verifyHash(Eip191Prefix.hash(message), signature, publicKey);
    }

    /** 验证哈希签名。 */
    public static boolean verifyHash(byte[] hash, Signature signature, byte[] publicKey) {
        if (!(signature instanceof EvmSignature evmSig)) {
            return false;
        }
        try {
            Secp256k1SignatureValidator.requireCanonicalLegacyV(evmSig.bytes());
            return Secp256k1Signer.verify(hash, evmSig.getR(), evmSig.getS(), publicKey);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * 从 EIP-191 消息 + 65 字节签名反算签名者地址（ecrecover）。
     * 后端验签的最常用入口：前端 MetaMask `personal_sign` 出来的 hex 解成 byte[]，传进来即可。
     */
    public static EvmAddress recoverAddress(byte[] message, byte[] signature) {
        Secp256k1SignatureValidator.requireCanonicalLegacyV(signature);
        return EvmAddress.recover(Eip191Prefix.hash(message), signature);
    }

    /** {@link #recoverAddress(byte[], byte[])} 的字符串重载。 */
    public static EvmAddress recoverAddress(String message, byte[] signature) {
        Secp256k1SignatureValidator.requireCanonicalLegacyV(signature);
        return EvmAddress.recover(Eip191Prefix.hash(message), signature);
    }

    /** {@link #recoverAddress(byte[], byte[])} 的 Signature 重载。 */
    public static EvmAddress recoverAddress(byte[] message, Signature signature) {
        return recoverAddress(message, signature.bytes());
    }

    /** {@link #recoverAddress(byte[], byte[])} 的字符串 + Signature 重载。 */
    public static EvmAddress recoverAddress(String message, Signature signature) {
        return recoverAddress(message, signature.bytes());
    }

    /**
     * 判断签名是否由 {@code expected} 地址签出。验签失败 / 签名格式错误均返回 false，不抛异常。
     */
    public static boolean verifyMessageAddress(byte[] message, byte[] signature, EvmAddress expected) {
        if (expected == null) return false;
        try {
            return expected.equals(recoverAddress(message, signature));
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** {@link #verifyMessageAddress(byte[], byte[], EvmAddress)} 的字符串重载。 */
    public static boolean verifyMessageAddress(String message, byte[] signature, EvmAddress expected) {
        if (expected == null) return false;
        try {
            return expected.equals(recoverAddress(message, signature));
        } catch (RuntimeException e) {
            return false;
        }
    }
}
