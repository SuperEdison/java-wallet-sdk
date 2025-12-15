package io.github.superedison.web3.crypto.hash;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.*;

/**
 * SHA-256 单元测试
 * 使用 NIST 标准测试向量验证
 */
@DisplayName("SHA-256 哈希算法测试")
class Sha256Test {

    @Nested
    @DisplayName("hash(byte[]) 方法测试")
    class HashBytesTest {

        @Test
        @DisplayName("空字节数组应该返回正确的哈希")
        void hashEmptyBytes() {
            byte[] input = new byte[0];
            byte[] hash = Sha256.hash(input);

            assertThat(hash).hasSize(32);
            // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            assertThat(bytesToHex(hash))
                    .isEqualTo("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        }

        @Test
        @DisplayName("\"abc\" 应该返回 NIST 标准测试向量结果")
        void hashAbcBytes() {
            byte[] input = "abc".getBytes(StandardCharsets.UTF_8);
            byte[] hash = Sha256.hash(input);

            assertThat(hash).hasSize(32);
            // NIST SHA-256 test vector for "abc"
            assertThat(bytesToHex(hash))
                    .isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        }

        @Test
        @DisplayName("\"hello\" 应该返回正确的哈希")
        void hashHelloBytes() {
            byte[] input = "hello".getBytes(StandardCharsets.UTF_8);
            byte[] hash = Sha256.hash(input);

            assertThat(hash).hasSize(32);
            // SHA256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
            assertThat(bytesToHex(hash))
                    .isEqualTo("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
        }
    }

    @Nested
    @DisplayName("hash(String) 方法测试")
    class HashStringTest {

        @Test
        @DisplayName("空字符串应该返回正确的哈希")
        void hashEmptyString() {
            byte[] hash = Sha256.hash("");

            assertThat(hash).hasSize(32);
            assertThat(bytesToHex(hash))
                    .isEqualTo("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        }

        @Test
        @DisplayName("NIST 长消息测试向量")
        void hashLongMessage() {
            // NIST test vector: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            String input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
            byte[] hash = Sha256.hash(input);

            assertThat(hash).hasSize(32);
            assertThat(bytesToHex(hash))
                    .isEqualTo("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
        }
    }

    @Nested
    @DisplayName("doubleHash 方法测试 (比特币使用)")
    class DoubleHashTest {

        @Test
        @DisplayName("双重哈希应该等于 SHA256(SHA256(input))")
        void doubleHashEqualsNestedHash() {
            byte[] input = "test".getBytes(StandardCharsets.UTF_8);

            byte[] doubleHash = Sha256.doubleHash(input);
            byte[] nestedHash = Sha256.hash(Sha256.hash(input));

            assertThat(doubleHash).isEqualTo(nestedHash);
        }

        @Test
        @DisplayName("比特币区块头双重哈希测试")
        void bitcoinDoubleHashTest() {
            byte[] input = "hello".getBytes(StandardCharsets.UTF_8);
            byte[] doubleHash = Sha256.doubleHash(input);

            assertThat(doubleHash).hasSize(32);

            // 验证确定性
            byte[] doubleHash2 = Sha256.doubleHash(input);
            assertThat(doubleHash).isEqualTo(doubleHash2);
        }

        @Test
        @DisplayName("空数据双重哈希")
        void doubleHashEmpty() {
            byte[] input = new byte[0];
            byte[] doubleHash = Sha256.doubleHash(input);

            assertThat(doubleHash).hasSize(32);
            // SHA256(SHA256(""))
            byte[] expected = Sha256.hash(Sha256.hash(input));
            assertThat(doubleHash).isEqualTo(expected);
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

            byte[] hashMultiple = Sha256.hash(block1, block2);
            byte[] hashConcat = Sha256.hash("hello world");

            assertThat(hashMultiple).isEqualTo(hashConcat);
        }

        @Test
        @DisplayName("三个数据块连接")
        void hashThreeBlocks() {
            byte[] block1 = "a".getBytes(StandardCharsets.UTF_8);
            byte[] block2 = "b".getBytes(StandardCharsets.UTF_8);
            byte[] block3 = "c".getBytes(StandardCharsets.UTF_8);

            byte[] hashMultiple = Sha256.hash(block1, block2, block3);
            byte[] hashConcat = Sha256.hash("abc");

            assertThat(hashMultiple).isEqualTo(hashConcat);
        }
    }

    @Nested
    @DisplayName("hashHex 方法测试")
    class HashHexTest {

        @Test
        @DisplayName("hashHex 应该返回小写十六进制字符串")
        void hashHexReturnsLowercase() {
            byte[] input = "test".getBytes(StandardCharsets.UTF_8);
            String hex = Sha256.hashHex(input);

            assertThat(hex)
                    .hasSize(64)
                    .matches("[0-9a-f]+");
        }

        @Test
        @DisplayName("hashHex 应该与已知值匹配")
        void hashHexKnownValue() {
            byte[] input = "abc".getBytes(StandardCharsets.UTF_8);
            String hex = Sha256.hashHex(input);

            assertThat(hex)
                    .isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        }
    }

    @Nested
    @DisplayName("HMAC-SHA256 方法测试")
    class HmacTest {

        @Test
        @DisplayName("HMAC-SHA256 应该返回 32 字节结果")
        void hmacReturns32Bytes() {
            byte[] key = "secret".getBytes(StandardCharsets.UTF_8);
            byte[] data = "message".getBytes(StandardCharsets.UTF_8);

            byte[] hmac = Sha256.hmac(key, data);

            assertThat(hmac).hasSize(32);
        }

        @Test
        @DisplayName("RFC 4231 测试向量 - Test Case 1")
        void hmacRfc4231TestCase1() {
            // Key = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (20 bytes)
            byte[] key = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
            // Data = "Hi There"
            byte[] data = "Hi There".getBytes(StandardCharsets.UTF_8);

            byte[] hmac = Sha256.hmac(key, data);

            // Expected HMAC-SHA256 = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
            assertThat(bytesToHex(hmac))
                    .isEqualTo("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        }

        @Test
        @DisplayName("RFC 4231 测试向量 - Test Case 2")
        void hmacRfc4231TestCase2() {
            // Key = "Jefe"
            byte[] key = "Jefe".getBytes(StandardCharsets.UTF_8);
            // Data = "what do ya want for nothing?"
            byte[] data = "what do ya want for nothing?".getBytes(StandardCharsets.UTF_8);

            byte[] hmac = Sha256.hmac(key, data);

            // Expected HMAC-SHA256 = 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
            assertThat(bytesToHex(hmac))
                    .isEqualTo("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        }

        @Test
        @DisplayName("相同密钥和数据应该产生相同结果")
        void hmacIsDeterministic() {
            byte[] key = "key".getBytes(StandardCharsets.UTF_8);
            byte[] data = "data".getBytes(StandardCharsets.UTF_8);

            byte[] hmac1 = Sha256.hmac(key, data);
            byte[] hmac2 = Sha256.hmac(key, data);

            assertThat(hmac1).isEqualTo(hmac2);
        }

        @Test
        @DisplayName("不同密钥应该产生不同结果")
        void hmacDifferentKeys() {
            byte[] key1 = "key1".getBytes(StandardCharsets.UTF_8);
            byte[] key2 = "key2".getBytes(StandardCharsets.UTF_8);
            byte[] data = "data".getBytes(StandardCharsets.UTF_8);

            byte[] hmac1 = Sha256.hmac(key1, data);
            byte[] hmac2 = Sha256.hmac(key2, data);

            assertThat(hmac1).isNotEqualTo(hmac2);
        }
    }

    @Nested
    @DisplayName("边界条件测试")
    class EdgeCaseTest {

        @Test
        @DisplayName("单字节数据应该正确处理")
        void hashSingleByte() {
            byte[] input = new byte[]{0x61}; // 'a'
            byte[] hash = Sha256.hash(input);

            assertThat(hash).hasSize(32);
            // SHA256("a") = ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb
            assertThat(bytesToHex(hash))
                    .isEqualTo("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb");
        }

        @Test
        @DisplayName("大数据块应该正确处理")
        void hashLargeData() {
            byte[] largeData = new byte[1024 * 1024]; // 1MB
            for (int i = 0; i < largeData.length; i++) {
                largeData[i] = (byte) (i % 256);
            }

            byte[] hash = Sha256.hash(largeData);

            assertThat(hash).hasSize(32);
            // 验证确定性
            byte[] hash2 = Sha256.hash(largeData);
            assertThat(hash).isEqualTo(hash2);
        }

        @Test
        @DisplayName("多次哈希同一数据应该返回相同结果")
        void hashIsDeterministic() {
            byte[] input = "deterministic test".getBytes(StandardCharsets.UTF_8);

            byte[] hash1 = Sha256.hash(input);
            byte[] hash2 = Sha256.hash(input);
            byte[] hash3 = Sha256.hash(input);

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