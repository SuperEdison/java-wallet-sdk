package io.github.superedison.web3.kms.aws;

import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.signer.SignatureScheme;
import io.github.superedison.web3.core.signer.SigningKey;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;
import io.github.superedison.web3.kms.DerSignatures;
import io.github.superedison.web3.kms.SubjectPublicKeyInfos;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * AWS KMS 托管的 secp256k1 签名密钥（EVM / TRON 热钱包）。
 *
 * KMS Key 必须满足：
 *   KeyUsage   = SIGN_VERIFY
 *   KeySpec    = ECC_SECG_P256K1
 *
 * 工作流程：
 *   1. 构造时调 GetPublicKey，从 X.509 SubjectPublicKeyInfo 取出 65 字节非压缩公钥并缓存。
 *   2. sign(hash) 调 Sign(MessageType=DIGEST, Algorithm=ECDSA_SHA_256)，
 *      解析 DER → (r, s)，low-S 规范化，再用缓存公钥反算 recovery id (v)。
 *
 * 安全/语义：
 *   - 私钥永远不离开 AWS，destroy() 只丢弃本地公钥缓存与 KmsClient 引用。
 *   - KmsClient 由调用方管理生命周期，本类不会 close 它（通常多个 Key 共享一个 client）。
 */
public final class AwsKmsSecp256k1Key implements SigningKey {

    private KmsClient kms;
    private final String keyId;
    private byte[] publicKey;          // 65 bytes uncompressed: 04 || X || Y
    private volatile boolean destroyed;

    public AwsKmsSecp256k1Key(KmsClient kms, String keyId) {
        if (kms == null) throw new IllegalArgumentException("KmsClient must not be null");
        if (keyId == null || keyId.isEmpty()) throw new IllegalArgumentException("keyId must not be empty");
        this.kms = kms;
        this.keyId = keyId;
        byte[] spki = kms.getPublicKey(GetPublicKeyRequest.builder().keyId(keyId).build())
                .publicKey().asByteArray();
        this.publicKey = SubjectPublicKeyInfos.parseSecp256k1Uncompressed(spki);
    }

    @Override
    public Signature sign(byte[] hash) {
        checkNotDestroyed();
        if (hash == null || hash.length != 32) {
            throw new IllegalArgumentException("Message hash must be 32 bytes");
        }

        SignResponse resp = kms.sign(SignRequest.builder()
                .keyId(keyId)
                .messageType(MessageType.DIGEST)
                .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                .message(SdkBytes.fromByteArray(hash))
                .build());

        DerSignatures.RS rs = DerSignatures.parse(resp.signature().asByteArray());
        BigInteger r = rs.r();
        BigInteger s = DerSignatures.normalizeLowS(rs.s());

        byte[] rBytes = DerSignatures.toFixed32(r);
        byte[] sBytes = DerSignatures.toFixed32(s);

        int recId = -1;
        for (int i = 0; i < 4; i++) {
            byte[] recovered = Secp256k1Signer.recoverPublicKey(hash, rBytes, sBytes, i);
            if (recovered != null && Arrays.equals(recovered, publicKey)) {
                recId = i;
                break;
            }
        }
        if (recId == -1) {
            throw new IllegalStateException("Could not recover v from KMS signature");
        }

        return new Secp256k1Signer.Secp256k1Signature(rBytes, sBytes, recId);
    }

    @Override
    public byte[] getPublicKey() {
        checkNotDestroyed();
        return publicKey.clone();
    }

    @Override
    public SignatureScheme getScheme() {
        return SignatureScheme.ECDSA_SECP256K1;
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
        return "AwsKmsSecp256k1Key{keyId=" + keyId + "}";
    }
}
