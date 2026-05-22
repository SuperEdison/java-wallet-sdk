package io.github.superedison.web3.kms.aws;

import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.signer.SignatureScheme;
import io.github.superedison.web3.crypto.ecc.Ed25519Signer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * AwsKmsEd25519Key 端到端 round-trip 测试。
 *
 * 与 secp256k1 测试同样的思路——用真实本地 {@link Ed25519Signer} 当 KMS 内部密钥，
 * mock KmsClient 返回 X.509 SPKI（Ed25519 / RFC 8410）和 64 字节原始 Ed25519 签名。
 */
@DisplayName("AwsKmsEd25519Key round-trip (mock KmsClient)")
class AwsKmsEd25519KeyTest {

    private static final byte[] PRIVATE_KEY = new byte[32];
    static { for (int i = 0; i < 32; i++) PRIVATE_KEY[i] = (byte) (i + 1); }

    private static final String KEY_ID = "alias/test-sol-hot";

    /** Ed25519 OID per RFC 8410. */
    private static final ASN1ObjectIdentifier OID_ED25519 = new ASN1ObjectIdentifier("1.3.101.112");

    private static byte[] spkiOfEd25519(byte[] pub32) throws Exception {
        return new SubjectPublicKeyInfo(new AlgorithmIdentifier(OID_ED25519), pub32).getEncoded();
    }

    private static KmsClient stubKmsClient(Ed25519Signer localSigner) throws Exception {
        KmsClient kms = mock(KmsClient.class);

        byte[] spki = spkiOfEd25519(localSigner.getPublicKey());
        GetPublicKeyResponse pkResp = GetPublicKeyResponse.builder()
                .publicKey(SdkBytes.fromByteArray(spki))
                .build();
        when(kms.getPublicKey(any(GetPublicKeyRequest.class))).thenReturn(pkResp);

        when(kms.sign(any(SignRequest.class))).thenAnswer(inv -> {
            SignRequest req = inv.getArgument(0);
            byte[] message = req.message().asByteArray();
            // 本地 Ed25519 直接签消息，返回 64 字节原始签名
            byte[] sig = localSigner.signRaw(message);
            return SignResponse.builder().signature(SdkBytes.fromByteArray(sig)).build();
        });

        return kms;
    }

    @Test
    @DisplayName("构造时从 SPKI 解出 32 字节原始 Ed25519 公钥，与本地一致")
    void cachesPublicKeyFromSpki() throws Exception {
        try (Ed25519Signer localSigner = new Ed25519Signer(PRIVATE_KEY)) {
            KmsClient kms = stubKmsClient(localSigner);

            try (AwsKmsEd25519Key kmsKey = new AwsKmsEd25519Key(kms, KEY_ID)) {
                byte[] kmsPub = kmsKey.getPublicKey();
                assertThat(kmsPub).hasSize(32).isEqualTo(localSigner.getPublicKey());
                assertThat(kmsKey.getScheme()).isEqualTo(SignatureScheme.ED25519);
                assertThat(kmsKey.getKeyId()).isEqualTo(KEY_ID);
            }
        }
    }

    @Test
    @DisplayName("sign(message) 返回 64 字节原始签名，能被 Ed25519Signer.verify 通过")
    void signRoundTripVerifies() throws Exception {
        try (Ed25519Signer localSigner = new Ed25519Signer(PRIVATE_KEY)) {
            KmsClient kms = stubKmsClient(localSigner);

            try (AwsKmsEd25519Key kmsKey = new AwsKmsEd25519Key(kms, KEY_ID)) {
                byte[] message = "hello solana via aws kms".getBytes();

                Signature sig = kmsKey.sign(message);
                assertThat(sig.scheme()).isEqualTo(SignatureScheme.ED25519);
                byte[] sigBytes = sig.bytes();
                assertThat(sigBytes).hasSize(64);

                assertThat(Ed25519Signer.verify(message, sigBytes, kmsKey.getPublicKey())).isTrue();

                // 与本地直接签 message 等价
                byte[] localSigBytes = localSigner.signRaw(message);
                assertThat(sigBytes).isEqualTo(localSigBytes);
            }
        }
    }

    @Test
    @DisplayName("destroy() 后 sign / getPublicKey 都拒绝")
    void destroyMakesKeyUnusable() throws Exception {
        try (Ed25519Signer localSigner = new Ed25519Signer(PRIVATE_KEY)) {
            KmsClient kms = stubKmsClient(localSigner);

            AwsKmsEd25519Key kmsKey = new AwsKmsEd25519Key(kms, KEY_ID);
            kmsKey.destroy();

            assertThat(kmsKey.isDestroyed()).isTrue();
            assertThatThrownBy(() -> kmsKey.sign(new byte[]{1, 2, 3}))
                    .isInstanceOf(IllegalStateException.class);
            assertThatThrownBy(kmsKey::getPublicKey)
                    .isInstanceOf(IllegalStateException.class);
        }
    }
}
