package io.github.superedison.web3.kms.aws;

import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.signer.SignatureScheme;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;

import java.math.BigInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * AwsKmsSecp256k1Key 端到端 round-trip 测试。
 *
 * 策略：用真实本地 {@link Secp256k1Signer} 当"KMS 内部的密钥"，
 * 通过 Mockito 把 {@link KmsClient#getPublicKey(GetPublicKeyRequest)} 与
 * {@link KmsClient#sign(SignRequest)} 拦截，按 AWS KMS 的真实编码格式（X.509 SPKI / DER ECDSA）返回，
 * 这样可以验证：
 *   1. AwsKmsSecp256k1Key 从 SPKI 正确解出 65 字节非压缩公钥
 *   2. sign(hash) 解析 DER -&gt; low-S -&gt; 反算 v 后，r/s/v 拼出来的签名能被本地校验通过
 *   3. v 反算的公钥与缓存公钥一致
 */
@DisplayName("AwsKmsSecp256k1Key round-trip (mock KmsClient)")
class AwsKmsSecp256k1KeyTest {

    private static final byte[] PRIVATE_KEY = new byte[]{
            (byte) 0x4c, (byte) 0x0d, (byte) 0xa4, (byte) 0xf3, (byte) 0x4d, (byte) 0x5f, (byte) 0x6a, (byte) 0x88,
            (byte) 0xc6, (byte) 0x9c, (byte) 0xa4, (byte) 0xe1, (byte) 0x4d, (byte) 0x52, (byte) 0x2c, (byte) 0x8e,
            (byte) 0xbb, (byte) 0xa1, (byte) 0x09, (byte) 0xb1, (byte) 0x2b, (byte) 0x07, (byte) 0x0d, (byte) 0x14,
            (byte) 0x9d, (byte) 0x6f, (byte) 0xb5, (byte) 0x52, (byte) 0xae, (byte) 0xa9, (byte) 0x16, (byte) 0x82
    };

    private static final String KEY_ID = "alias/test-evm-hot";

    /** 把本地 secp256k1 65 字节非压缩公钥包成 X.509 SubjectPublicKeyInfo (DER)。 */
    private static byte[] spkiOfSecp256k1(byte[] uncompressedPubKey) throws Exception {
        AlgorithmIdentifier algo = new AlgorithmIdentifier(
                X9ObjectIdentifiers.id_ecPublicKey,
                SECObjectIdentifiers.secp256k1
        );
        return new SubjectPublicKeyInfo(algo, uncompressedPubKey).getEncoded();
    }

    /** 把 (r, s) 编为 DER。 */
    private static byte[] toDer(BigInteger r, BigInteger s) throws Exception {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        return new DERSequence(v).getEncoded();
    }

    /**
     * 构造一个"假装是 AWS KMS"的 KmsClient：
     *  - getPublicKey: 返回 localSigner 公钥的 SPKI
     *  - sign: 用 localSigner 本地签名 hash，把得到的 (r, s) DER 化返回
     */
    private static KmsClient stubKmsClient(Secp256k1Signer localSigner) throws Exception {
        KmsClient kms = mock(KmsClient.class);

        byte[] spki = spkiOfSecp256k1(localSigner.getPublicKey());
        GetPublicKeyResponse pkResp = GetPublicKeyResponse.builder()
                .publicKey(SdkBytes.fromByteArray(spki))
                .build();
        when(kms.getPublicKey(any(GetPublicKeyRequest.class))).thenReturn(pkResp);

        when(kms.sign(any(SignRequest.class))).thenAnswer(inv -> {
            SignRequest req = inv.getArgument(0);
            byte[] hash = req.message().asByteArray();
            // 本地签出 r/s/v，按 AWS 行为只返回 DER(r,s)
            Secp256k1Signer.Secp256k1Signature sig =
                    (Secp256k1Signer.Secp256k1Signature) localSigner.sign(hash);
            BigInteger r = new BigInteger(1, sig.r());
            BigInteger s = new BigInteger(1, sig.s());
            byte[] der = toDer(r, s);
            return SignResponse.builder().signature(SdkBytes.fromByteArray(der)).build();
        });

        return kms;
    }

    @Test
    @DisplayName("构造时从 SPKI 解出与本地一致的 65 字节非压缩公钥")
    void cachesPublicKeyFromSpki() throws Exception {
        try (Secp256k1Signer localSigner = new Secp256k1Signer(PRIVATE_KEY)) {
            KmsClient kms = stubKmsClient(localSigner);

            try (AwsKmsSecp256k1Key kmsKey = new AwsKmsSecp256k1Key(kms, KEY_ID)) {
                byte[] kmsPub = kmsKey.getPublicKey();
                assertThat(kmsPub).hasSize(65);
                assertThat(kmsPub[0]).isEqualTo((byte) 0x04);
                assertThat(kmsPub).isEqualTo(localSigner.getPublicKey());
                assertThat(kmsKey.getScheme()).isEqualTo(SignatureScheme.ECDSA_SECP256K1);
                assertThat(kmsKey.getKeyId()).isEqualTo(KEY_ID);
            }
        }
    }

    @Test
    @DisplayName("sign(hash) round-trip：DER -> low-S -> v 反算后，签名能被本地 verify 通过，且 v 反算公钥等于缓存公钥")
    void signRoundTripVerifies() throws Exception {
        try (Secp256k1Signer localSigner = new Secp256k1Signer(PRIVATE_KEY)) {
            KmsClient kms = stubKmsClient(localSigner);

            try (AwsKmsSecp256k1Key kmsKey = new AwsKmsSecp256k1Key(kms, KEY_ID)) {
                byte[] hash = new byte[32];
                for (int i = 0; i < 32; i++) hash[i] = (byte) (i * 7 + 3);

                Signature sig = kmsKey.sign(hash);
                assertThat(sig).isInstanceOf(Secp256k1Signer.Secp256k1Signature.class);
                Secp256k1Signer.Secp256k1Signature rsv = (Secp256k1Signer.Secp256k1Signature) sig;

                // r/s 长度严格 32 字节
                assertThat(rsv.r()).hasSize(32);
                assertThat(rsv.s()).hasSize(32);

                // v ∈ {0, 1, 2, 3}，且 v 反算公钥必须等于 KMS 缓存公钥
                assertThat(rsv.v()).isBetween(0, 3);
                byte[] recovered = Secp256k1Signer.recoverPublicKey(hash, rsv.r(), rsv.s(), rsv.v());
                assertThat(recovered).isEqualTo(kmsKey.getPublicKey());

                // (r, s) 能被标准 secp256k1 verify 通过
                assertThat(Secp256k1Signer.verify(hash, rsv.r(), rsv.s(), kmsKey.getPublicKey())).isTrue();
            }
        }
    }

    @Test
    @DisplayName("destroy() 后 sign / getPublicKey 都拒绝")
    void destroyMakesKeyUnusable() throws Exception {
        try (Secp256k1Signer localSigner = new Secp256k1Signer(PRIVATE_KEY)) {
            KmsClient kms = stubKmsClient(localSigner);

            AwsKmsSecp256k1Key kmsKey = new AwsKmsSecp256k1Key(kms, KEY_ID);
            kmsKey.destroy();

            assertThat(kmsKey.isDestroyed()).isTrue();
            assertThatThrownBy(() -> kmsKey.sign(new byte[32]))
                    .isInstanceOf(IllegalStateException.class);
            assertThatThrownBy(kmsKey::getPublicKey)
                    .isInstanceOf(IllegalStateException.class);
        }
    }
}
