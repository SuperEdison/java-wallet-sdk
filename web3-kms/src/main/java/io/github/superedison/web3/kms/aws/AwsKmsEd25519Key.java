package io.github.superedison.web3.kms.aws;

import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.signer.SignatureScheme;
import io.github.superedison.web3.core.signer.SigningKey;
import io.github.superedison.web3.crypto.ecc.Ed25519Signer;
import io.github.superedison.web3.kms.SubjectPublicKeyInfos;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

/**
 * AWS KMS 托管的 Ed25519 签名密钥（Solana 等链热钱包）。
 *
 * KMS Key 必须满足：
 *   KeyUsage = SIGN_VERIFY
 *   KeySpec  = ECC_NIST_EDWARDS25519
 *
 * 工作流程：
 *   1. 构造时调 GetPublicKey，取 X.509 SubjectPublicKeyInfo 中的 32 字节原始 Ed25519 公钥并缓存。
 *   2. sign(message) 调 Sign(MessageType=RAW, Algorithm=ED25519_SHA_512)，KMS 内部完成
 *      "SHA-512 over R||A||M" 的完整 Ed25519，返回 64 字节原始签名。
 *
 * 注意：
 *   - 与 {@link Ed25519Signer#sign(byte[])} 语义一致——传入的是"原始消息"，不是预哈希。
 *   - AWS KMS 对 RAW MessageType 有 4 KB 上限；Solana 交易远小于这个限制。
 *   - destroy() 仅清本地公钥缓存与 KmsClient 引用；私钥始终在 AWS。
 */
public final class AwsKmsEd25519Key implements SigningKey {

    private KmsClient kms;
    private final String keyId;
    private byte[] publicKey;          // 32 bytes raw Ed25519
    private volatile boolean destroyed;

    public AwsKmsEd25519Key(KmsClient kms, String keyId) {
        if (kms == null) throw new IllegalArgumentException("KmsClient must not be null");
        if (keyId == null || keyId.isEmpty()) throw new IllegalArgumentException("keyId must not be empty");
        this.kms = kms;
        this.keyId = keyId;
        byte[] spki = kms.getPublicKey(GetPublicKeyRequest.builder().keyId(keyId).build())
                .publicKey().asByteArray();
        this.publicKey = SubjectPublicKeyInfos.parseEd25519(spki);
    }

    /**
     * 对原始消息签名（不是预哈希）。Solana 交易消息直接传入即可。
     */
    @Override
    public Signature sign(byte[] message) {
        checkNotDestroyed();
        if (message == null) {
            throw new IllegalArgumentException("Message must not be null");
        }

        SignResponse resp = kms.sign(SignRequest.builder()
                .keyId(keyId)
                .messageType(MessageType.RAW)
                .signingAlgorithm(SigningAlgorithmSpec.ED25519_SHA_512)
                .message(SdkBytes.fromByteArray(message))
                .build());

        return new Ed25519Signer.Ed25519Signature(resp.signature().asByteArray());
    }

    @Override
    public byte[] getPublicKey() {
        checkNotDestroyed();
        return publicKey.clone();
    }

    @Override
    public SignatureScheme getScheme() {
        return SignatureScheme.ED25519;
    }

    /** KMS Key ID / ARN / Alias，便于上层做地址映射。 */
    public String getKeyId() {
        return keyId;
    }

    @Override
    public void destroy() {
        if (!destroyed) {
            publicKey = null;
            kms = null;
            destroyed = true;
        }
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    private void checkNotDestroyed() {
        if (destroyed) throw new IllegalStateException("SigningKey has been destroyed");
    }

    @Override
    public String toString() {
        return "AwsKmsEd25519Key{keyId=" + keyId + "}";
    }
}
