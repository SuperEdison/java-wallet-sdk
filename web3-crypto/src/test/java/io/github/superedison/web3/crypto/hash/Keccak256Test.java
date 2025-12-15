package io.github.superedison.web3.crypto.hash;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.*;

/**
 * Keccak256 单元测试
 * 使用已知的测试向量验证哈希算法的正确性
 */
@DisplayName("Keccak256 哈希算法测试")
class Keccak256Test {

    @Nested
    @DisplayName("hash(byte[]) 方法测试")
    class HashBytesTest {

        @Test
        @DisplayName("空字节数组应该返回正确的哈希")
        void hashEmptyBytes() {
            byte[] input = new byte[0];
            byte[] hash = Keccak256.hash(input);

            assertThat(hash).hasSize(32);
            // Keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
            assertThat(bytesToHex(hash))
                    .isEqualTo("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
        }

        @Test
        @DisplayName("\"hello\" 应该返回正确的哈希")
        void hashHelloBytes() {
            byte[] input = "hello".getBytes(StandardCharsets.UTF_8);
            byte[] hash = Keccak256.hash(input);

            assertThat(hash).hasSize(32);
            // Keccak256("hello") = 1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8
            assertThat(bytesToHex(hash))
                    .isEqualTo("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8");
        }

        @Test
        @DisplayName("以太坊地址计算测试")
        void hashForEthereumAddress() {
            // 已知的公钥哈希测试
            byte[] input = hexToBytes("0000000000000000000000000000000000000000000000000000000000000001");
            byte[] hash = Keccak256.hash(input);

            assertThat(hash).hasSize(32);
        }
    }

    @Nested
    @DisplayName("hash(String) 方法测试")
    class HashStringTest {

        @Test
        @DisplayName("空字符串应该返回正确的哈希")
        void hashEmptyString() {
            byte[] hash = Keccak256.hash("");

            assertThat(hash).hasSize(32);
            assertThat(bytesToHex(hash))
                    .isEqualTo("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
        }

        @Test
        @DisplayName("\"hello world\" 应该返回正确的哈希")
        void hashHelloWorld() {
            byte[] hash = Keccak256.hash("hello world");

            assertThat(hash).hasSize(32);
            // Keccak256("hello world") = 47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad
            assertThat(bytesToHex(hash))
                    .isEqualTo("47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad");
        }

        @Test
        @DisplayName("中文字符串应该正确处理UTF-8编码")
        void hashChineseString() {
            byte[] hash = Keccak256.hash("你好");

            assertThat(hash).hasSize(32);
            // 确保哈希一致性
            byte[] hash2 = Keccak256.hash("你好");
            assertThat(hash).isEqualTo(hash2);
        }
    }

    @Nested
    @DisplayName("hash(byte[]...) 多数据块方法测试")
    class HashMultipleBlocksTest {

        @Test
        @DisplayName("连接两个数据块应该等于单独哈希连接后的数据")
        void hashMultipleBlocksEqualsConcat() {
            byte[] block1 = "hello".getBytes(StandardCharsets.UTF_8);
            byte[] block2 = " world".getBytes(StandardCharsets.UTF_8);

            byte[] hashMultiple = Keccak256.hash(block1, block2);
            byte[] hashConcat = Keccak256.hash("hello world");

            assertThat(hashMultiple).isEqualTo(hashConcat);
        }

        @Test
        @DisplayName("空数据块数组应该返回空字节哈希")
        void hashEmptyBlocks() {
            byte[] hash = Keccak256.hash(new byte[0], new byte[0]);

            assertThat(hash).hasSize(32);
            // 相当于 hash 空数据
            assertThat(bytesToHex(hash))
                    .isEqualTo("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
        }
    }

    @Nested
    @DisplayName("hashHex 方法测试")
    class HashHexTest {

        @Test
        @DisplayName("hashHex 应该返回小写十六进制字符串")
        void hashHexReturnsLowercase() {
            byte[] input = "test".getBytes(StandardCharsets.UTF_8);
            String hex = Keccak256.hashHex(input);

            assertThat(hex)
                    .hasSize(64)
                    .matches("[0-9a-f]+");
        }

        @Test
        @DisplayName("hashHex 结果应该与手动转换一致")
        void hashHexConsistentWithManualConversion() {
            byte[] input = "hello".getBytes(StandardCharsets.UTF_8);
            String hex = Keccak256.hashHex(input);
            byte[] hash = Keccak256.hash(input);

            assertThat(hex).isEqualTo(bytesToHex(hash));
        }
    }

    @Nested
    @DisplayName("hashHexWithPrefix 方法测试")
    class HashHexWithPrefixTest {

        @Test
        @DisplayName("hashHexWithPrefix 应该返回 0x 前缀的十六进制字符串")
        void hashHexWithPrefixHas0xPrefix() {
            byte[] input = "test".getBytes(StandardCharsets.UTF_8);
            String hex = Keccak256.hashHexWithPrefix(input);

            assertThat(hex)
                    .hasSize(66)
                    .startsWith("0x")
                    .matches("0x[0-9a-f]+");
        }

        @Test
        @DisplayName("hashHexWithPrefix 应该与 hashHex 加前缀一致")
        void hashHexWithPrefixConsistentWithHashHex() {
            byte[] input = "hello".getBytes(StandardCharsets.UTF_8);
            String withPrefix = Keccak256.hashHexWithPrefix(input);
            String withoutPrefix = Keccak256.hashHex(input);

            assertThat(withPrefix).isEqualTo("0x" + withoutPrefix);
        }
    }

    @Nested
    @DisplayName("边界条件测试")
    class EdgeCaseTest {

        @Test
        @DisplayName("大数据块应该正确处理")
        void hashLargeData() {
            byte[] largeData = new byte[1024 * 1024]; // 1MB
            for (int i = 0; i < largeData.length; i++) {
                largeData[i] = (byte) (i % 256);
            }

            byte[] hash = Keccak256.hash(largeData);

            assertThat(hash).hasSize(32);
            // 确保结果一致
            byte[] hash2 = Keccak256.hash(largeData);
            assertThat(hash).isEqualTo(hash2);
        }

        @Test
        @DisplayName("单字节数据应该正确处理")
        void hashSingleByte() {
            byte[] input = new byte[]{0x00};
            byte[] hash = Keccak256.hash(input);

            assertThat(hash).hasSize(32);
            // Keccak256(0x00) = bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a
            assertThat(bytesToHex(hash))
                    .isEqualTo("bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a");
        }

        @Test
        @DisplayName("多次哈希同一数据应该返回相同结果")
        void hashIsDeterministic() {
            byte[] input = "deterministic".getBytes(StandardCharsets.UTF_8);

            byte[] hash1 = Keccak256.hash(input);
            byte[] hash2 = Keccak256.hash(input);
            byte[] hash3 = Keccak256.hash(input);

            assertThat(hash1).isEqualTo(hash2).isEqualTo(hash3);
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