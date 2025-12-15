package io.github.superedison.web3.crypto.ecc;

import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.signer.SignatureScheme;
import io.github.superedison.web3.core.signer.SigningKey;
import io.github.superedison.web3.crypto.util.SecureBytes;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;

/**
 * Ed25519 椭圆曲线签名器
 * 用于 Solana, NEAR, Polkadot 等链
 *
 * 安全注意事项：
 * - 私钥是"能力"，不是"数据"，不能被读取
 * - 使用完毕后必须调用 close() 或 destroy() 擦除私钥
 * - 推荐使用 try-with-resources 语法
 *
 * 示例：
 * <pre>{@code
 * try (Ed25519Signer signer = new Ed25519Signer(privateKey)) {
 *     Signature sig = signer.sign(message);
 * } // 自动擦除私钥
 * }</pre>
 */
public class Ed25519Signer implements SigningKey {

    private final byte[] privateKey;
    private final byte[] publicKey;
    private final Ed25519PrivateKeyParameters privateKeyParams;
    private volatile boolean destroyed = false;

    /**
     * 从私钥创建签名器
     * @param privateKey 32字节私钥（种子）
     */
    public Ed25519Signer(byte[] privateKey) {
        if (privateKey == null || privateKey.length != 32) {
            throw new IllegalArgumentException("Private key must be 32 bytes");
        }
        this.privateKey = SecureBytes.copy(privateKey);
        this.privateKeyParams = new Ed25519PrivateKeyParameters(privateKey, 0);
        this.publicKey = privateKeyParams.generatePublicKey().getEncoded();
    }

    /**
     * 从私钥派生公钥
     * @param privateKey 32字节私钥
     * @return 32字节公钥
     */
    public static byte[] derivePublicKey(byte[] privateKey) {
        Ed25519PrivateKeyParameters privParams = new Ed25519PrivateKeyParameters(privateKey, 0);
        return privParams.generatePublicKey().getEncoded();
    }

    /**
     * 对消息签名（SigningKey 接口实现）
     * 注意：Ed25519 对消息直接签名，不需要预先哈希
     *
     * @param message 任意长度消息（Ed25519 内部会进行哈希）
     * @return 签名结果
     * @throws IllegalStateException 如果签名器已销毁
     */
    @Override
    public Signature sign(byte[] message) {
        checkNotDestroyed();
        org.bouncycastle.crypto.signers.Ed25519Signer signer =
                new org.bouncycastle.crypto.signers.Ed25519Signer();
        signer.init(true, privateKeyParams);
        signer.update(message, 0, message.length);
        byte[] signatureBytes = signer.generateSignature();
        return new Ed25519Signature(signatureBytes);
    }

    /**
     * 对消息签名（返回原始字节数组，便于兼容）
     * @param message 任意长度消息
     * @return 64字节签名
     */
    public byte[] signRaw(byte[] message) {
        checkNotDestroyed();
        org.bouncycastle.crypto.signers.Ed25519Signer signer =
                new org.bouncycastle.crypto.signers.Ed25519Signer();
        signer.init(true, privateKeyParams);
        signer.update(message, 0, message.length);
        return signer.generateSignature();
    }

    private void checkNotDestroyed() {
        if (destroyed) {
            throw new IllegalStateException("SigningKey has been destroyed");
        }
    }

    /**
     * 验证签名
     * @param message 消息
     * @param signature 64字节签名
     * @param publicKey 32字节公钥
     * @return 是否有效
     */
    public static boolean verify(byte[] message, byte[] signature, byte[] publicKey) {
        if (signature == null || signature.length != 64) {
            return false;
        }
        if (publicKey == null || publicKey.length != 32) {
            return false;
        }

        try {
            Ed25519PublicKeyParameters pubParams = new Ed25519PublicKeyParameters(publicKey, 0);
            org.bouncycastle.crypto.signers.Ed25519Signer verifier =
                    new org.bouncycastle.crypto.signers.Ed25519Signer();
            verifier.init(false, pubParams);
            verifier.update(message, 0, message.length);
            return verifier.verifySignature(signature);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 使用当前密钥对验证签名
     */
    public boolean verify(byte[] message, byte[] signature) {
        return verify(message, signature, publicKey);
    }

    /**
     * 获取公钥（32字节）
     */
    @Override
    public byte[] getPublicKey() {
        checkNotDestroyed();
        return SecureBytes.copy(publicKey);
    }

    /**
     * 获取签名算法类型
     */
    @Override
    public SignatureScheme getScheme() {
        return SignatureScheme.ED25519;
    }

    /**
     * 销毁私钥
     * 调用后私钥将被清零，SigningKey 不可再使用
     */
    @Override
    public void destroy() {
        if (!destroyed) {
            SecureBytes.secureWipe(privateKey);
            destroyed = true;
        }
    }

    /**
     * 是否已销毁
     */
    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    /**
     * 安全的 toString 实现，不暴露私钥
     */
    @Override
    public String toString() {
        return "Ed25519Signer{***REDACTED***}";
    }

    /**
     * Ed25519 签名结果，实现通用 Signature 接口
     */
    public record Ed25519Signature(byte[] signatureBytes) implements Signature {

        /**
         * 获取签名字节（64字节）
         */
        @Override
        public byte[] bytes() {
            return signatureBytes.clone();
        }

        /**
         * 获取签名算法
         */
        @Override
        public SignatureScheme scheme() {
            return SignatureScheme.ED25519;
        }
    }
}