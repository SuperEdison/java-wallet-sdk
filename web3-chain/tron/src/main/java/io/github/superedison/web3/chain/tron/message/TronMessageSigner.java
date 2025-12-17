package io.github.superedison.web3.chain.tron.message;

import io.github.superedison.web3.chain.tron.internal.TronSignature;
import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;
import io.github.superedison.web3.crypto.hash.Sha256;
import io.github.superedison.web3.crypto.util.SecureBytes;

import java.nio.charset.StandardCharsets;

/**
 * TRON 消息签名器
 * 使用前缀: "\x19TRON Signed Message:\n{length}"
 */
public final class TronMessageSigner {

    private static final String PREFIX = "\u0019TRON Signed Message:\n";

    private TronMessageSigner() {}

    /**
     * 计算 TRON 消息哈希
     * hash = SHA256("\x19TRON Signed Message:\n" + len(message) + message)
     * @param message 原始消息
     * @return 32 字节哈希
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

    /**
     * 计算 TRON 消息哈希
     * @param message 原始消息字符串
     * @return 32 字节哈希
     */
    public static byte[] hashMessage(String message) {
        if (message == null) {
            throw new IllegalArgumentException("Message cannot be null");
        }
        return hashMessage(message.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 签名消息
     * @param message 原始消息
     * @param privateKey 32 字节私钥
     * @return 签名
     */
    public static Signature signMessage(byte[] message, byte[] privateKey) {
        byte[] hash = hashMessage(message);
        return signHash(hash, privateKey);
    }

    /**
     * 签名消息
     * @param message 原始消息字符串
     * @param privateKey 32 字节私钥
     * @return 签名
     */
    public static Signature signMessage(String message, byte[] privateKey) {
        byte[] hash = hashMessage(message);
        return signHash(hash, privateKey);
    }

    /**
     * 签名哈希
     * @param hash 32 字节哈希
     * @param privateKey 32 字节私钥
     * @return 签名
     */
    public static Signature signHash(byte[] hash, byte[] privateKey) {
        if (hash == null || hash.length != 32) {
            throw new IllegalArgumentException("Hash must be 32 bytes");
        }
        if (privateKey == null || privateKey.length != 32) {
            throw new IllegalArgumentException("Private key must be 32 bytes");
        }

        byte[] pkCopy = SecureBytes.copy(privateKey);
        try (Secp256k1Signer signer = new Secp256k1Signer(pkCopy)) {
            var sig = signer.sign(hash);
            if (!(sig instanceof Secp256k1Signer.Secp256k1Signature secpSig)) {
                throw new IllegalStateException("Unexpected signature type");
            }
            return TronSignature.fromSecp256k1Signature(secpSig);
        } finally {
            SecureBytes.secureWipe(pkCopy);
        }
    }

    /**
     * 验证消息签名
     * @param message 原始消息
     * @param signature 签名
     * @param publicKey 公钥
     * @return 如果签名有效返回 true
     */
    public static boolean verifyMessage(byte[] message, Signature signature, byte[] publicKey) {
        byte[] hash = hashMessage(message);
        return verifyHash(hash, signature, publicKey);
    }

    /**
     * 验证消息签名
     * @param message 原始消息字符串
     * @param signature 签名
     * @param publicKey 公钥
     * @return 如果签名有效返回 true
     */
    public static boolean verifyMessage(String message, Signature signature, byte[] publicKey) {
        byte[] hash = hashMessage(message);
        return verifyHash(hash, signature, publicKey);
    }

    /**
     * 验证哈希签名
     * @param hash 32 字节哈希
     * @param signature 签名
     * @param publicKey 公钥
     * @return 如果签名有效返回 true
     */
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
}
