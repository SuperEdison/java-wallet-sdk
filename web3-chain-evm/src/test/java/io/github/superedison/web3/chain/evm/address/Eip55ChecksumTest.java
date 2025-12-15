package io.github.superedison.web3.chain.evm.address;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.*;

/**
 * Eip55Checksum 单元测试
 * 测试 EIP-55 地址校验和算法
 */
@DisplayName("Eip55Checksum EIP-55校验和测试")
class Eip55ChecksumTest {

    @Nested
    @DisplayName("apply 方法测试")
    class ApplyTest {

        @ParameterizedTest
        @DisplayName("EIP-55 官方测试向量")
        @CsvSource({
                "5aaeb6053f3e94c9b9a09f33669435e7ef1beaed, 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
                "fb6916095ca1df60bb79ce92ce3ea74c37c5d359, 0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
                "dbf03b407c01e7cd3cbea99509d93f8dddc8c6fb, 0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
                "d1220a0cf47c7b9be7a2e6ba89f429762e7b9adb, 0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"
        })
        void officialTestVectors(String input, String expected) {
            String result = Eip55Checksum.apply(input);

            assertThat(result).isEqualTo(expected);
        }

        @Test
        @DisplayName("全小写输入应该正确转换")
        void lowercaseInput() {
            String result = Eip55Checksum.apply("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");

            assertThat(result)
                    .startsWith("0x")
                    .hasSize(42);
        }

        @Test
        @DisplayName("全大写输入应该正确转换")
        void uppercaseInput() {
            String result = Eip55Checksum.apply("5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED");

            assertThat(result).isEqualTo("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
        }

        @Test
        @DisplayName("混合大小写输入应该归一化后转换")
        void mixedCaseInput() {
            String result = Eip55Checksum.apply("5aAeB6053f3E94c9B9A09F33669435e7ef1BeAed");

            assertThat(result).isEqualTo("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
        }

        @Test
        @DisplayName("零地址应该正确处理")
        void zeroAddress() {
            String result = Eip55Checksum.apply("0000000000000000000000000000000000000000");

            assertThat(result).isEqualTo("0x0000000000000000000000000000000000000000");
        }

        @Test
        @DisplayName("全F地址应该正确处理")
        void allFsAddress() {
            String result = Eip55Checksum.apply("ffffffffffffffffffffffffffffffffffffffff");

            assertThat(result).startsWith("0x");
            assertThat(result).hasSize(42);
        }
    }

    @Nested
    @DisplayName("verify 方法测试")
    class VerifyTest {

        @ParameterizedTest
        @DisplayName("正确的校验和地址应该返回true")
        @ValueSource(strings = {
                "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
                "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
                "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
                "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"
        })
        void validChecksumReturnsTrue(String address) {
            assertThat(Eip55Checksum.verify(address)).isTrue();
        }

        @ParameterizedTest
        @DisplayName("全小写地址应该验证失败（除非是全数字）")
        @ValueSource(strings = {
                "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
                "0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359"
        })
        void lowercaseFailsVerification(String address) {
            assertThat(Eip55Checksum.verify(address)).isFalse();
        }

        @ParameterizedTest
        @DisplayName("全大写地址应该验证失败（除非是全数字）")
        @ValueSource(strings = {
                "0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED",
                "0xFB6916095CA1DF60BB79CE92CE3EA74C37C5D359"
        })
        void uppercaseFailsVerification(String address) {
            assertThat(Eip55Checksum.verify(address)).isFalse();
        }

        @Test
        @DisplayName("全数字地址应该验证通过（大小写无关）")
        void allDigitsAddress() {
            // 全数字地址的校验和与大小写无关
            String allDigits = "0x1234567890123456789012345678901234567890";
            String result = Eip55Checksum.apply("1234567890123456789012345678901234567890");

            // 验证转换后的地址
            assertThat(Eip55Checksum.verify(result)).isTrue();
        }

        @ParameterizedTest
        @DisplayName("无效格式应该返回false")
        @ValueSource(strings = {
                "",
                "0x",
                "0x123",
                "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", // 无前缀
                "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAe", // 太短
                "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAedX", // 太长
                "0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG" // 无效字符
        })
        void invalidFormatReturnsFalse(String address) {
            assertThat(Eip55Checksum.verify(address)).isFalse();
        }

        @Test
        @DisplayName("null应该返回false")
        void nullReturnsFalse() {
            assertThat(Eip55Checksum.verify(null)).isFalse();
        }

        @Test
        @DisplayName("错误的校验和应该返回false")
        void wrongChecksumReturnsFalse() {
            // 故意修改一个字符的大小写
            String wrongChecksum = "0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"; // 第一个A应该是小写

            assertThat(Eip55Checksum.verify(wrongChecksum)).isFalse();
        }
    }

    @Nested
    @DisplayName("apply 和 verify 一致性测试")
    class ConsistencyTest {

        @Test
        @DisplayName("apply结果应该通过verify验证")
        void applyResultPassesVerify() {
            String[] addresses = {
                    "5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
                    "fb6916095ca1df60bb79ce92ce3ea74c37c5d359",
                    "dbf03b407c01e7cd3cbea99509d93f8dddc8c6fb",
                    "d1220a0cf47c7b9be7a2e6ba89f429762e7b9adb",
                    "0000000000000000000000000000000000000000",
                    "ffffffffffffffffffffffffffffffffffffffff"
            };

            for (String address : addresses) {
                String checksummed = Eip55Checksum.apply(address);
                assertThat(Eip55Checksum.verify(checksummed))
                        .as("Address %s should pass verification after apply", address)
                        .isTrue();
            }
        }

        @Test
        @DisplayName("连续apply应该返回相同结果")
        void applyIsIdempotent() {
            String address = "5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";

            String first = Eip55Checksum.apply(address);
            // 去掉0x前缀再apply
            String second = Eip55Checksum.apply(first.substring(2));

            assertThat(second).isEqualTo(first);
        }
    }

    @Nested
    @DisplayName("边界条件测试")
    class EdgeCaseTest {

        @Test
        @DisplayName("地址只有数字时验证")
        void addressWithOnlyDigits() {
            String allDigits = "1234567890123456789012345678901234567890";
            String result = Eip55Checksum.apply(allDigits);

            // 全数字地址不需要大小写变化
            assertThat(result).isEqualTo("0x" + allDigits);
        }

        @Test
        @DisplayName("地址只有字母时验证")
        void addressWithOnlyLetters() {
            String allLetters = "abcdefabcdefabcdefabcdefabcdefabcdefabcd";
            String result = Eip55Checksum.apply(allLetters);

            assertThat(result)
                    .startsWith("0x")
                    .hasSize(42);
            assertThat(Eip55Checksum.verify(result)).isTrue();
        }

        @Test
        @DisplayName("交替大小写测试")
        void alternatingCase() {
            String address = "aAbBcCdDeEfF0011223344556677889900aabbcc";
            String result = Eip55Checksum.apply(address);

            assertThat(Eip55Checksum.verify(result)).isTrue();
        }
    }
}