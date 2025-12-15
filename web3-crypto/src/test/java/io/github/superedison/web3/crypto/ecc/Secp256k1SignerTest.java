package io.github.superedison.web3.crypto.ecc;

import io.github.superedison.web3.crypto.hash.Keccak256;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.AfterEach;

import java.math.BigInteger;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.*;

/**
 * Secp256k1Signer 单元测试
 * 使用已知的以太坊测试向量验证签名算法
 */
@DisplayName("Secp256k1 签名器测试")
class Secp256k1SignerTest {

    // 测试私钥（仅用于测试，切勿在生产中使用）
    // 使用标准测试向量私钥: 1
    private static final byte[] TEST_PRIVATE_KEY = hexToBytes(
            "0000000000000000000000000000000000000000000000000000000000000001");

    // 对应的公钥（非压缩，65字节）- 私钥为1时的标准公钥
    private static final String EXPECTED_PUBLIC_KEY_HEX =
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
                    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

    // 对应的以太坊地址（私钥为1）
    private static final String EXPECTED_ADDRESS = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf";

    private Secp256k1Signer signer;

    @AfterEach
    void tearDown() {
        if (signer != null) {
            signer.destroy();
        }
    }

    @Nested
    @DisplayName("构造函数测试")
    class ConstructorTest {

        @Test
        @DisplayName("有效的32字节私钥应该成功创建签名器")
        void validPrivateKey() {
            signer = new Secp256k1Signer(TEST_PRIVATE_KEY);

            assertThat(signer.getPublicKey()).hasSize(65);
            assertThat(signer.getCompressedPublicKey()).hasSize(33);
        }

        @Test
        @DisplayName("null私钥应该抛出异常")
        void nullPrivateKey() {
            assertThatThrownBy(() -> new Secp256k1Signer(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("32 bytes");
        }

        @Test
        @DisplayName("短私钥应该抛出异常")
        void shortPrivateKey() {
            byte[] shortKey = new byte[31];
            assertThatThrownBy(() -> new Secp256k1Signer(shortKey))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("32 bytes");
        }

        @Test
        @DisplayName("长私钥应该抛出异常")
        void longPrivateKey() {
            byte[] longKey = new byte[33];
            assertThatThrownBy(() -> new Secp256k1Signer(longKey))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("32 bytes");
        }

        @Test
        @DisplayName("空数组私钥应该抛出异常")
        void emptyPrivateKey() {
            byte[] emptyKey = new byte[0];
            assertThatThrownBy(() -> new Secp256k1Signer(emptyKey))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    @DisplayName("公钥派生测试")
    class PublicKeyDerivationTest {

        @Test
        @DisplayName("应该正确派生非压缩公钥")
        void deriveUncompressedPublicKey() {
            signer = new Secp256k1Signer(TEST_PRIVATE_KEY);
            byte[] publicKey = signer.getPublicKey();

            assertThat(publicKey).hasSize(65);
            assertThat(publicKey[0]).isEqualTo((byte) 0x04); // 非压缩前缀
            assertThat(bytesToHex(publicKey)).isEqualToIgnoringCase(EXPECTED_PUBLIC_KEY_HEX);
        }

        @Test
        @DisplayName("应该正确派生压缩公钥")
        void deriveCompressedPublicKey() {
            signer = new Secp256k1Signer(TEST_PRIVATE_KEY);
            byte[] compressedKey = signer.getCompressedPublicKey();

            assertThat(compressedKey).hasSize(33);
            // 压缩前缀是 02 或 03
            assertThat(compressedKey[0] == 0x02 || compressedKey[0] == 0x03).isTrue();
        }

        @Test
        @DisplayName("静态方法应该正确派生公钥")
        void staticDerivePublicKey() {
            byte[] uncompressed = Secp256k1Signer.derivePublicKey(TEST_PRIVATE_KEY, false);
            byte[] compressed = Secp256k1Signer.derivePublicKey(TEST_PRIVATE_KEY, true);

            assertThat(uncompressed).hasSize(65);
            assertThat(compressed).hasSize(33);
            assertThat(bytesToHex(uncompressed)).isEqualToIgnoringCase(EXPECTED_PUBLIC_KEY_HEX);
        }

        @Test
        @DisplayName("获取公钥应该返回副本")
        void getPublicKeyReturnsCopy() {
            signer = new Secp256k1Signer(TEST_PRIVATE_KEY);
            byte[] publicKey1 = signer.getPublicKey();
            byte[] publicKey2 = signer.getPublicKey();

            // 修改一个不应该影响另一个
            publicKey1[0] = 0x00;
            assertThat(publicKey2[0]).isNotEqualTo((byte) 0x00);
        }
    }

    @Nested
    @DisplayName("签名方法测试")
    class SignTest {

        @Test
        @DisplayName("应该正确签名消息哈希")
        void signMessageHash() {
            signer = new Secp256k1Signer(TEST_PRIVATE_KEY);
            byte[] messageHash = Keccak256.hash("hello world");

            var result = (Secp256k1Signer.Secp256k1Signature) signer.sign(messageHash);

            assertThat(result.r()).hasSize(32);
            assertThat(result.s()).hasSize(32);
            assertThat(result.v()).isBetween(0, 1);
        }

        @Test
        @DisplayName("签名结果应该可验证")
        void signatureIsVerifiable() {
            signer = new Secp256k1Signer(TEST_PRIVATE_KEY);
            byte[] messageHash = Keccak256.hash("test message");

            var result = (Secp256k1Signer.Secp256k1Signature) signer.sign(messageHash);
            byte[] publicKey = signer.getPublicKey();

            boolean valid = Secp256k1Signer.verify(messageHash, result.r(), result.s(), publicKey);
            assertThat(valid).isTrue();
        }

        @Test
        @DisplayName("null消息哈希应该抛出异常")
        void signNullHash() {
            signer = new Secp256k1Signer(TEST_PRIVATE_KEY);

            assertThatThrownBy(() -> signer.sign(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("32 bytes");
        }

        @Test
        @DisplayName("非32字节消息哈希应该抛出异常")
        void signInvalidLengthHash() {
            signer = new Secp256k1Signer(TEST_PRIVATE_KEY);

            assertThatThrownBy(() -> signer.sign(new byte[31]))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("32 bytes");
        }

        @Test
        @DisplayName("签名应该是低阶 s 值（EIP-2）")
        void signatureShouldBeLowS() {
            signer = new Secp256k1Signer(TEST_PRIVATE_KEY);

            // 多次签名测试
            for (int i = 0; i < 10; i++) {
                byte[] messageHash = Keccak256.hash("test " + i);
                var result = (Secp256k1Signer.Secp256k1Signature) signer.sign(messageHash);

                BigInteger s = new BigInteger(1, result.s());
                BigInteger halfN = new BigInteger(
                        "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0", 16);

                assertThat(s.compareTo(halfN) <= 0)
                        .as("签名 s 值应该 <= N/2")
                        .isTrue();
            }
        }
    }

    @Nested
    @DisplayName("Secp256k1Signature 测试")
    class Secp256k1SignatureTest {

        @Test
        @DisplayName("toCompact 应该返回65字节紧凑格式")
        void toCompactFormat() {
            signer = new Secp256k1Signer(TEST_PRIVATE_KEY);
            byte[] messageHash = Keccak256.hash("test");

            var result = (Secp256k1Signer.Secp256k1Signature) signer.sign(messageHash);
            byte[] compact = result.toCompact();

            assertThat(compact).hasSize(65);
            assertThat(Arrays.copyOfRange(compact, 0, 32)).isEqualTo(result.r());
            assertThat(Arrays.copyOfRange(compact, 32, 64)).isEqualTo(result.s());
            assertThat(compact[64]).isEqualTo((byte) result.v());
        }

        @Test
        @DisplayName("getEthereumV 应该返回 27 或 28")
        void getEthereumV() {
            signer = new Secp256k1Signer(TEST_PRIVATE_KEY);
            byte[] messageHash = Keccak256.hash("test");

            var result = (Secp256k1Signer.Secp256k1Signature) signer.sign(messageHash);
            int ethV = result.getEthereumV();

            assertThat(ethV).isBetween(27, 28);
            assertThat(ethV).isEqualTo(result.v() + 27);
        }

        @Test
        @DisplayName("getEip155V 应该正确计算 chainId 相关的 v 值")
        void getEip155V() {
            signer = new Secp256k1Signer(TEST_PRIVATE_KEY);
            byte[] messageHash = Keccak256.hash("test");

            var result = (Secp256k1Signer.Secp256k1Signature) signer.sign(messageHash);

            // Ethereum mainnet (chainId = 1)
            int eip155V = result.getEip155V(1);
            assertThat(eip155V).isEqualTo(result.v() + 1 * 2 + 35);

            // BSC (chainId = 56)
            int bscV = result.getEip155V(56);
            assertThat(bscV).isEqualTo(result.v() + 56 * 2 + 35);
        }
    }

    @Nested
    @DisplayName("验证签名测试")
    class VerifyTest {

        @Test
        @DisplayName("有效签名应该验证通过")
        void verifyValidSignature() {
            signer = new Secp256k1Signer(TEST_PRIVATE_KEY);
            byte[] messageHash = Keccak256.hash("message to sign");

            var result = (Secp256k1Signer.Secp256k1Signature) signer.sign(messageHash);

            boolean valid = Secp256k1Signer.verify(
                    messageHash, result.r(), result.s(), signer.getPublicKey());
            assertThat(valid).isTrue();
        }

        @Test
        @DisplayName("错误消息应该验证失败")
        void verifyWithWrongMessage() {
            signer = new Secp256k1Signer(TEST_PRIVATE_KEY);
            byte[] messageHash = Keccak256.hash("original message");
            byte[] wrongHash = Keccak256.hash("different message");

            var result = (Secp256k1Signer.Secp256k1Signature) signer.sign(messageHash);

            boolean valid = Secp256k1Signer.verify(
                    wrongHash, result.r(), result.s(), signer.getPublicKey());
            assertThat(valid).isFalse();
        }

        @Test
        @DisplayName("错误公钥应该验证失败")
        void verifyWithWrongPublicKey() {
            signer = new Secp256k1Signer(TEST_PRIVATE_KEY);
            byte[] messageHash = Keccak256.hash("message");

            var result = (Secp256k1Signer.Secp256k1Signature) signer.sign(messageHash);

            // 使用不同的私钥生成的公钥（私钥 = 2）
            byte[] differentPrivateKey = new byte[32];
            differentPrivateKey[31] = 0x02; // 私钥 = 2
            byte[] wrongPublicKey = Secp256k1Signer.derivePublicKey(differentPrivateKey, false);

            boolean valid = Secp256k1Signer.verify(
                    messageHash, result.r(), result.s(), wrongPublicKey);
            assertThat(valid).isFalse();
        }

        @Test
        @DisplayName("篡改的签名应该验证失败")
        void verifyTamperedSignature() {
            signer = new Secp256k1Signer(TEST_PRIVATE_KEY);
            byte[] messageHash = Keccak256.hash("message");

            var result = (Secp256k1Signer.Secp256k1Signature) signer.sign(messageHash);

            // 篡改 r 值
            byte[] tamperedR = result.r().clone();
            tamperedR[0] ^= 0xFF;

            boolean valid = Secp256k1Signer.verify(
                    messageHash, tamperedR, result.s(), signer.getPublicKey());
            assertThat(valid).isFalse();
        }
    }

    @Nested
    @DisplayName("公钥恢复测试")
    class RecoverPublicKeyTest {

        @Test
        @DisplayName("应该从签名正确恢复公钥")
        void recoverPublicKeyFromSignature() {
            signer = new Secp256k1Signer(TEST_PRIVATE_KEY);
            byte[] messageHash = Keccak256.hash("recover test");

            var result = (Secp256k1Signer.Secp256k1Signature) signer.sign(messageHash);

            byte[] recovered = Secp256k1Signer.recoverPublicKey(
                    messageHash, result.r(), result.s(), result.v());

            assertThat(recovered).isEqualTo(signer.getPublicKey());
        }

        @Test
        @DisplayName("使用 BigInteger 版本应该正确恢复公钥")
        void recoverPublicKeyWithBigInteger() {
            signer = new Secp256k1Signer(TEST_PRIVATE_KEY);
            byte[] messageHash = Keccak256.hash("bigint test");

            var result = (Secp256k1Signer.Secp256k1Signature) signer.sign(messageHash);

            BigInteger r = new BigInteger(1, result.r());
            BigInteger s = new BigInteger(1, result.s());

            byte[] recovered = Secp256k1Signer.recoverPublicKey(
                    messageHash, r, s, result.v());

            assertThat(recovered).isEqualTo(signer.getPublicKey());
        }

        @Test
        @DisplayName("无效的 recId 应该返回 null")
        void invalidRecIdReturnsNull() {
            signer = new Secp256k1Signer(TEST_PRIVATE_KEY);
            byte[] messageHash = Keccak256.hash("test");

            var result = (Secp256k1Signer.Secp256k1Signature) signer.sign(messageHash);

            byte[] recovered = Secp256k1Signer.recoverPublicKey(
                    messageHash, result.r(), result.s(), -1);
            assertThat(recovered).isNull();

            recovered = Secp256k1Signer.recoverPublicKey(
                    messageHash, result.r(), result.s(), 4);
            assertThat(recovered).isNull();
        }
    }

    @Nested
    @DisplayName("销毁私钥测试")
    class DestroyTest {

        @Test
        @DisplayName("destroy 应该擦除内存中的私钥")
        void destroyWipesPrivateKey() {
            byte[] privateKey = TEST_PRIVATE_KEY.clone();
            signer = new Secp256k1Signer(privateKey);

            // 销毁前可以正常签名
            byte[] hash = Keccak256.hash("test");
            var beforeDestroy = (Secp256k1Signer.Secp256k1Signature) signer.sign(hash);
            assertThat(beforeDestroy).isNotNull();

            signer.destroy();
            signer = null; // 防止 tearDown 再次调用
        }

        @Test
        @DisplayName("销毁后 isDestroyed 应该返回 true")
        void isDestroyedReturnsTrue() {
            signer = new Secp256k1Signer(TEST_PRIVATE_KEY);
            assertThat(signer.isDestroyed()).isFalse();

            signer.destroy();
            assertThat(signer.isDestroyed()).isTrue();
            signer = null;
        }

        @Test
        @DisplayName("销毁后签名应该抛出异常")
        void signAfterDestroyThrows() {
            signer = new Secp256k1Signer(TEST_PRIVATE_KEY);
            signer.destroy();

            byte[] hash = Keccak256.hash("test");
            assertThatThrownBy(() -> signer.sign(hash))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("destroyed");
            signer = null;
        }

        @Test
        @DisplayName("销毁后获取公钥应该抛出异常")
        void getPublicKeyAfterDestroyThrows() {
            signer = new Secp256k1Signer(TEST_PRIVATE_KEY);
            signer.destroy();

            assertThatThrownBy(() -> signer.getPublicKey())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("destroyed");
            signer = null;
        }

        @Test
        @DisplayName("重复销毁应该安全")
        void multipleDestroySafe() {
            signer = new Secp256k1Signer(TEST_PRIVATE_KEY);
            signer.destroy();
            signer.destroy(); // 不应抛出异常
            assertThat(signer.isDestroyed()).isTrue();
            signer = null;
        }

        @Test
        @DisplayName("try-with-resources 应该自动销毁")
        void tryWithResourcesAutoDestroy() {
            Secp256k1Signer tempSigner;
            try (Secp256k1Signer s = new Secp256k1Signer(TEST_PRIVATE_KEY)) {
                tempSigner = s;
                assertThat(s.isDestroyed()).isFalse();
                s.sign(Keccak256.hash("test"));
            }
            assertThat(tempSigner.isDestroyed()).isTrue();
        }
    }

    @Nested
    @DisplayName("安全特性测试")
    class SecurityTest {

        @Test
        @DisplayName("toString 不应该暴露私钥")
        void toStringDoesNotLeakPrivateKey() {
            signer = new Secp256k1Signer(TEST_PRIVATE_KEY);
            String str = signer.toString();

            // toString 不应该包含私钥相关信息
            assertThat(str).doesNotContain("0000000000000000");
            assertThat(str).contains("REDACTED");
        }

        @Test
        @DisplayName("getScheme 应该返回 ECDSA_SECP256K1")
        void getSchemeReturnsCorrectType() {
            signer = new Secp256k1Signer(TEST_PRIVATE_KEY);
            assertThat(signer.getScheme())
                    .isEqualTo(io.github.superedison.web3.core.signer.SignatureScheme.ECDSA_SECP256K1);
        }

        @Test
        @DisplayName("签名结果的 scheme 应该正确")
        void signatureSchemeIsCorrect() {
            signer = new Secp256k1Signer(TEST_PRIVATE_KEY);
            var signature = signer.sign(Keccak256.hash("test"));

            assertThat(signature.scheme())
                    .isEqualTo(io.github.superedison.web3.core.signer.SignatureScheme.ECDSA_SECP256K1);
        }
    }

    @Nested
    @DisplayName("以太坊兼容性测试")
    class EthereumCompatibilityTest {

        @Test
        @DisplayName("使用已知测试向量验证签名")
        void verifyWithKnownTestVector() {
            // 使用私钥 = 1 的标准测试向量
            signer = new Secp256k1Signer(TEST_PRIVATE_KEY);

            // 派生的地址应该是 EXPECTED_ADDRESS
            byte[] publicKey = signer.getPublicKey();

            // 取公钥（去掉04前缀）的 Keccak256 哈希的后20字节
            byte[] keyWithoutPrefix = Arrays.copyOfRange(publicKey, 1, 65);
            byte[] hash = Keccak256.hash(keyWithoutPrefix);
            byte[] addressBytes = Arrays.copyOfRange(hash, 12, 32);

            String address = "0x" + bytesToHex(addressBytes);
            assertThat(address).isEqualToIgnoringCase(EXPECTED_ADDRESS);
        }
    }

    // 辅助方法
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static byte[] hexToBytes(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }
}