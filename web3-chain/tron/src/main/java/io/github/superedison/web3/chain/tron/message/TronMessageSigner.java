package io.github.superedison.web3.chain.tron.message;

import io.github.superedison.web3.chain.tron.address.TronAddress;
import io.github.superedison.web3.chain.tron.internal.TronSignature;
import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.signer.SigningKey;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;
import io.github.superedison.web3.crypto.hash.Sha256;

import java.nio.charset.StandardCharsets;

/**
 * TRON 消息签名器，前缀: {@code "\x19TRON Signed Message:\n{length}"}。
 *
 * 不再接收 {@code byte[] privateKey}——私钥是"能力"不是"数据"，统一通过 {@link SigningKey}
 * 抽象，所以本地 secp256k1 私钥、AWS KMS、HSM、硬件钱包都能复用同一套入口。
 */
public final class TronMessageSigner {

    private static final String PREFIX = "TRON Signed Message:\n";

    private TronMessageSigner() {}

    /**
     * 计算 TRON 消息哈希。
     * hash = SHA256("\x19TRON Signed Message:\n" + len(message) + message)
     */
    public static byte[] hashMessage(byte[] message) {
        if (message == null) {
            throw new IllegalArgumentException("Message cannot be null");
        }
        byte[] prefix = PREFIX.getBytes(StandardCharsets.UTF_8);
        byte[] length = String.valueOf(message.length).getBytes(StandardCharsets.UTF_8);

        byte[] toHash = new byte[prefix.length + length.length + message.length];
        System.arraycopy(prefix, 0, toHash, 0, prefix.length);
        System.arraycopy(length, 0, toHash, prefix.length, length.length);
        System.arraycopy(message, 0, toHash, prefix.length + length.length, message.length);

        return Sha256.hash(toHash);
    }

    public static byte[] hashMessage(String message) {
        if (message == null) {
            throw new IllegalArgumentException("Message cannot be null");
        }
        return hashMessage(message.getBytes(StandardCharsets.UTF_8));
    }

    /** 签名原始字节消息。 */
    public static Signature signMessage(byte[] message, SigningKey signingKey) {
        return signHash(hashMessage(message), signingKey);
    }

    /** 签名字符串消息。 */
    public static Signature signMessage(String message, SigningKey signingKey) {
        return signHash(hashMessage(message), signingKey);
    }

    /** 直接签 32 字节哈希。 */
    public static Signature signHash(byte[] hash, SigningKey signingKey) {
        if (hash == null || hash.length != 32) {
            throw new IllegalArgumentException("Hash must be 32 bytes");
        }
        var sig = signingKey.sign(hash);
        if (!(sig instanceof Secp256k1Signer.Secp256k1Signature secpSig)) {
            throw new IllegalStateException("Unexpected signature type: " + sig.getClass());
        }
        return TronSignature.fromSecp256k1Signature(secpSig);
    }

    /** 验证消息签名。 */
    public static boolean verifyMessage(byte[] message, Signature signature, byte[] publicKey) {
        return verifyHash(hashMessage(message), signature, publicKey);
    }

    /** 验证消息签名（字符串）。 */
    public static boolean verifyMessage(String message, Signature signature, byte[] publicKey) {
        return verifyHash(hashMessage(message), signature, publicKey);
    }

    /** 验证哈希签名。 */
    public static boolean verifyHash(byte[] hash, Signature signature, byte[] publicKey) {
        if (hash == null || hash.length != 32) {
            return false;
        }
        if (signature == null) {
            return false;
        }
        if (publicKey == null || (publicKey.length != 64 && publicKey.length != 65)) {
            return false;
        }

        byte[] sigBytes = signature.bytes();
        if (sigBytes.length != 65) {
            return false;
        }

        TronSignature tronSig = TronSignature.fromCompact(sigBytes);
        return Secp256k1Signer.verify(hash, tronSig.getR(), tronSig.getS(), publicKey);
    }

    /**
     * 从 TRON 消息 + 65 字节签名反算签名者地址（ecrecover）。
     * 后端验签的最常用入口。
     */
    public static TronAddress recoverAddress(byte[] message, byte[] signature) {
        return TronAddress.recover(hashMessage(message), signature);
    }

    /** {@link #recoverAddress(byte[], byte[])} 的字符串重载。 */
    public static TronAddress recoverAddress(String message, byte[] signature) {
        return TronAddress.recover(hashMessage(message), signature);
    }

    /** {@link #recoverAddress(byte[], byte[])} 的 Signature 重载。 */
    public static TronAddress recoverAddress(byte[] message, Signature signature) {
        return TronAddress.recover(hashMessage(message), signature.bytes());
    }

    /** {@link #recoverAddress(byte[], byte[])} 的字符串 + Signature 重载。 */
    public static TronAddress recoverAddress(String message, Signature signature) {
        return TronAddress.recover(hashMessage(message), signature.bytes());
    }

    /**
     * 判断签名是否由 {@code expected} 地址签出。验签失败 / 签名格式错误均返回 false，不抛异常。
     */
    public static boolean verifyMessageAddress(byte[] message, byte[] signature, TronAddress expected) {
        if (expected == null) return false;
        try {
            return expected.equals(recoverAddress(message, signature));
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** {@link #verifyMessageAddress(byte[], byte[], TronAddress)} 的字符串重载。 */
    public static boolean verifyMessageAddress(String message, byte[] signature, TronAddress expected) {
        if (expected == null) return false;
        try {
            return expected.equals(recoverAddress(message, signature));
        } catch (RuntimeException e) {
            return false;
        }
    }
}
