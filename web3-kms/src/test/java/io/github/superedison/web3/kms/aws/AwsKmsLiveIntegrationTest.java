package io.github.superedison.web3.kms.aws;

import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.signer.SignatureScheme;
import io.github.superedison.web3.crypto.ecc.Ed25519Signer;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DescribeKeyRequest;
import software.amazon.awssdk.services.kms.model.DescribeKeyResponse;
import software.amazon.awssdk.services.kms.model.KeySpec;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 真实 AWS KMS round-trip 集成测试。
 *
 * <p>需要以下环境变量；缺一个都会跳过整个测试类，不会让默认 CI 失败：
 * <ul>
 *   <li>{@code AWS_REGION} —— e.g. {@code ap-southeast-1}</li>
 *   <li>{@code AWS_ACCESS_KEY_ID}</li>
 *   <li>{@code AWS_SECRET_ACCESS_KEY}</li>
 *   <li>{@code AWS_KMS_KEY_ID} —— KMS Key ID / ARN / alias</li>
 * </ul>
 *
 * <p>本类带 {@code @Tag("integration")}，可以用
 * {@code mvn test -pl web3-kms -Dgroups=integration} 单独触发；
 * 默认 {@code mvn test} 会因为 surefire 没排除任何 group 而**也跑这套**，
 * 但 {@link EnabledIfEnvironmentVariable} 会在缺环境变量时 skip，不影响默认 CI。
 */
@Tag("integration")
@DisplayName("AWS KMS live round-trip (requires AWS credentials)")
@EnabledIfEnvironmentVariable(named = "AWS_KMS_KEY_ID", matches = ".+")
@EnabledIfEnvironmentVariable(named = "AWS_ACCESS_KEY_ID", matches = ".+")
@EnabledIfEnvironmentVariable(named = "AWS_SECRET_ACCESS_KEY", matches = ".+")
@EnabledIfEnvironmentVariable(named = "AWS_REGION", matches = ".+")
class AwsKmsLiveIntegrationTest {

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private static KmsClient buildKms() {
        return KmsClient.builder()
                .region(Region.of(System.getenv("AWS_REGION")))
                .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create(
                        System.getenv("AWS_ACCESS_KEY_ID"),
                        System.getenv("AWS_SECRET_ACCESS_KEY"))))
                .httpClient(UrlConnectionHttpClient.create())  // 轻量 JDK HTTP，避免 apache-client / commons-logging 坑
                .build();
    }

    @Test
    @DisplayName("GetPublicKey + Sign round-trip 与本地验证一致")
    void liveRoundTrip() {
        String keyId = System.getenv("AWS_KMS_KEY_ID");

        try (KmsClient kms = buildKms()) {
            // 先 DescribeKey 看下 KeySpec，再选 secp256k1 / Ed25519 分支
            DescribeKeyResponse desc = kms.describeKey(DescribeKeyRequest.builder().keyId(keyId).build());
            KeySpec spec = desc.keyMetadata().keySpec();

            System.out.println("[KMS-IT] KeyId=" + keyId);
            System.out.println("[KMS-IT] KeySpec=" + spec);
            System.out.println("[KMS-IT] KeyUsage=" + desc.keyMetadata().keyUsageAsString());
            System.out.println("[KMS-IT] Region=" + System.getenv("AWS_REGION"));

            switch (spec) {
                case ECC_SECG_P256_K1 -> verifySecp256k1(kms, keyId);
                case ECC_NIST_EDWARDS25519 -> verifyEd25519(kms, keyId);
                default -> throw new AssertionError(
                        "Unsupported KeySpec for web3-kms: " + spec
                                + " (expected ECC_SECG_P256_K1 or ECC_NIST_EDWARDS25519)");
            }
        }
    }

    private static void verifySecp256k1(KmsClient kms, String keyId) {
        try (AwsKmsSecp256k1Key kmsKey = new AwsKmsSecp256k1Key(kms, keyId)) {
            byte[] pubKey = kmsKey.getPublicKey();
            System.out.println("[KMS-IT] secp256k1 public key (65 bytes uncompressed):");
            System.out.println("[KMS-IT]   hex      = " + toHex(pubKey));
            System.out.println("[KMS-IT]   X        = " + toHex(java.util.Arrays.copyOfRange(pubKey, 1, 33)));
            System.out.println("[KMS-IT]   Y        = " + toHex(java.util.Arrays.copyOfRange(pubKey, 33, 65)));
            System.out.println("[KMS-IT]   prefix=" + String.format("%02x", pubKey[0]));
            System.out.println("[KMS-IT]   length=" + pubKey.length);

            // 用这把公钥派生 EVM / TRON 地址（同一公钥同一私钥）
            String evmAddr = io.github.superedison.web3.chain.evm.address.EvmAddress
                    .fromPublicKey(pubKey).toChecksumHex();
            String tronAddr = io.github.superedison.web3.chain.tron.address.TronAddress
                    .fromPublicKey(pubKey).toBase58();
            System.out.println("[KMS-IT]   EVM      = " + evmAddr);
            System.out.println("[KMS-IT]   TRON     = " + tronAddr);

            assertThat(pubKey).hasSize(65);
            assertThat(pubKey[0]).isEqualTo((byte) 0x04);
            assertThat(kmsKey.getScheme()).isEqualTo(SignatureScheme.ECDSA_SECP256K1);

            // sign + recover round-trip
            byte[] hash = new byte[32];
            for (int i = 0; i < 32; i++) hash[i] = (byte) (i * 13 + 7);

            Signature sig = kmsKey.sign(hash);
            assertThat(sig).isInstanceOf(Secp256k1Signer.Secp256k1Signature.class);
            Secp256k1Signer.Secp256k1Signature rsv = (Secp256k1Signer.Secp256k1Signature) sig;

            System.out.println("[KMS-IT] secp256k1 signature: r/s 32B each, v=" + rsv.v());

            // 严格几何校验：v 反算公钥必须等于 KMS 返回公钥
            byte[] recovered = Secp256k1Signer.recoverPublicKey(hash, rsv.r(), rsv.s(), rsv.v());
            assertThat(recovered).isEqualTo(pubKey);

            // 标准 ECDSA 验证
            assertThat(Secp256k1Signer.verify(hash, rsv.r(), rsv.s(), pubKey)).isTrue();

            System.out.println("[KMS-IT] ✅ secp256k1 round-trip OK — KMS 签名可被本地 verify，v 反算公钥与缓存公钥一致");
        }
    }

    private static void verifyEd25519(KmsClient kms, String keyId) {
        try (AwsKmsEd25519Key kmsKey = new AwsKmsEd25519Key(kms, keyId)) {
            byte[] pubKey = kmsKey.getPublicKey();
            System.out.println("[KMS-IT] Ed25519 public key (32 bytes raw):");
            System.out.println("[KMS-IT]   hex   = " + toHex(pubKey));
            System.out.println("[KMS-IT]   length=" + pubKey.length);

            assertThat(pubKey).hasSize(32);
            assertThat(kmsKey.getScheme()).isEqualTo(SignatureScheme.ED25519);

            byte[] message = "hello aws kms via web3-kms".getBytes();
            Signature sig = kmsKey.sign(message);
            byte[] sigBytes = sig.bytes();

            System.out.println("[KMS-IT] Ed25519 signature length=" + sigBytes.length);

            assertThat(sigBytes).hasSize(64);
            assertThat(Ed25519Signer.verify(message, sigBytes, pubKey)).isTrue();

            System.out.println("[KMS-IT] ✅ Ed25519 round-trip OK — KMS 签名可被本地 verify");
        }
    }
}
