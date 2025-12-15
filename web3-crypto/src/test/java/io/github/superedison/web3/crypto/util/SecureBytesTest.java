package io.github.superedison.web3.crypto.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.RepeatedTest;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.*;

/**
 * SecureBytes 单元测试
 * 测试安全字节数组操作工具类
 */
@DisplayName("SecureBytes 安全字节工具类测试")
class SecureBytesTest {

    @Nested
    @DisplayName("wipe 方法测试")
    class WipeTest {

        @Test
        @DisplayName("应该将所有字节填充为0")
        void wipeFillsWithZeros() {
            byte[] data = {1, 2, 3, 4, 5, 6, 7, 8};
            SecureBytes.wipe(data);

            assertThat(data).containsOnly((byte) 0);
        }

        @Test
        @DisplayName("空数组应该正常处理")
        void wipeEmptyArray() {
            byte[] data = new byte[0];
            SecureBytes.wipe(data);

            assertThat(data).isEmpty();
        }

        @Test
        @DisplayName("null应该安全处理")
        void wipeNullSafely() {
            assertThatCode(() -> SecureBytes.wipe(null))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("大数组应该正确擦除")
        void wipeLargeArray() {
            byte[] data = new byte[10000];
            Arrays.fill(data, (byte) 0xFF);

            SecureBytes.wipe(data);

            assertThat(data).containsOnly((byte) 0);
        }
    }

    @Nested
    @DisplayName("secureWipe 方法测试")
    class SecureWipeTest {

        @Test
        @DisplayName("应该最终将所有字节填充为0")
        void secureWipeFillsWithZeros() {
            byte[] data = {1, 2, 3, 4, 5, 6, 7, 8};
            SecureBytes.secureWipe(data);

            assertThat(data).containsOnly((byte) 0);
        }

        @Test
        @DisplayName("null应该安全处理")
        void secureWipeNullSafely() {
            assertThatCode(() -> SecureBytes.secureWipe(null))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("空数组应该正常处理")
        void secureWipeEmptyArray() {
            byte[] data = new byte[0];
            SecureBytes.secureWipe(data);

            assertThat(data).isEmpty();
        }
    }

    @Nested
    @DisplayName("wipeAll 方法测试")
    class WipeAllTest {

        @Test
        @DisplayName("应该擦除所有数组")
        void wipeAllArrays() {
            byte[] data1 = {1, 2, 3};
            byte[] data2 = {4, 5, 6};
            byte[] data3 = {7, 8, 9};

            SecureBytes.wipeAll(data1, data2, data3);

            assertThat(data1).containsOnly((byte) 0);
            assertThat(data2).containsOnly((byte) 0);
            assertThat(data3).containsOnly((byte) 0);
        }

        @Test
        @DisplayName("包含null的数组列表应该安全处理")
        void wipeAllWithNulls() {
            byte[] data1 = {1, 2, 3};
            byte[] data2 = null;
            byte[] data3 = {4, 5, 6};

            assertThatCode(() -> SecureBytes.wipeAll(data1, data2, data3))
                    .doesNotThrowAnyException();

            assertThat(data1).containsOnly((byte) 0);
            assertThat(data3).containsOnly((byte) 0);
        }

        @Test
        @DisplayName("空可变参数应该安全处理")
        void wipeAllEmpty() {
            assertThatCode(() -> SecureBytes.wipeAll())
                    .doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("copy 方法测试")
    class CopyTest {

        @Test
        @DisplayName("应该创建独立的副本")
        void copyCreatesIndependentCopy() {
            byte[] original = {1, 2, 3, 4, 5};
            byte[] copy = SecureBytes.copy(original);

            assertThat(copy).isEqualTo(original);
            assertThat(copy).isNotSameAs(original);

            // 修改副本不应该影响原数组
            copy[0] = 99;
            assertThat(original[0]).isEqualTo((byte) 1);
        }

        @Test
        @DisplayName("null应该返回null")
        void copyNullReturnsNull() {
            byte[] copy = SecureBytes.copy(null);
            assertThat(copy).isNull();
        }

        @Test
        @DisplayName("空数组应该返回空数组副本")
        void copyEmptyArray() {
            byte[] original = new byte[0];
            byte[] copy = SecureBytes.copy(original);

            assertThat(copy).isEmpty();
            assertThat(copy).isNotSameAs(original);
        }
    }

    @Nested
    @DisplayName("copyRange 方法测试")
    class CopyRangeTest {

        @Test
        @DisplayName("应该正确复制指定范围")
        void copyRangeCorrectly() {
            byte[] original = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
            byte[] range = SecureBytes.copyRange(original, 2, 6);

            assertThat(range).containsExactly((byte) 2, (byte) 3, (byte) 4, (byte) 5);
        }

        @Test
        @DisplayName("null应该返回null")
        void copyRangeNullReturnsNull() {
            byte[] range = SecureBytes.copyRange(null, 0, 5);
            assertThat(range).isNull();
        }

        @Test
        @DisplayName("从头开始复制")
        void copyRangeFromStart() {
            byte[] original = {1, 2, 3, 4, 5};
            byte[] range = SecureBytes.copyRange(original, 0, 3);

            assertThat(range).containsExactly((byte) 1, (byte) 2, (byte) 3);
        }

        @Test
        @DisplayName("复制到末尾")
        void copyRangeToEnd() {
            byte[] original = {1, 2, 3, 4, 5};
            byte[] range = SecureBytes.copyRange(original, 3, 5);

            assertThat(range).containsExactly((byte) 4, (byte) 5);
        }
    }

    @Nested
    @DisplayName("randomBytes 方法测试")
    class RandomBytesTest {

        @Test
        @DisplayName("应该返回指定长度的随机字节")
        void randomBytesCorrectLength() {
            byte[] random = SecureBytes.randomBytes(32);

            assertThat(random).hasSize(32);
        }

        @Test
        @DisplayName("两次调用应该返回不同的结果")
        @RepeatedTest(5)
        void randomBytesDifferent() {
            byte[] random1 = SecureBytes.randomBytes(32);
            byte[] random2 = SecureBytes.randomBytes(32);

            assertThat(random1).isNotEqualTo(random2);
        }

        @Test
        @DisplayName("长度为0应该返回空数组")
        void randomBytesZeroLength() {
            byte[] random = SecureBytes.randomBytes(0);

            assertThat(random).isEmpty();
        }

        @Test
        @DisplayName("大长度应该正常工作")
        void randomBytesLargeLength() {
            byte[] random = SecureBytes.randomBytes(1024);

            assertThat(random).hasSize(1024);
        }
    }

    @Nested
    @DisplayName("constantTimeEquals 方法测试")
    class ConstantTimeEqualsTest {

        @Test
        @DisplayName("相等的数组应该返回true")
        void equalArraysReturnTrue() {
            byte[] a = {1, 2, 3, 4, 5};
            byte[] b = {1, 2, 3, 4, 5};

            assertThat(SecureBytes.constantTimeEquals(a, b)).isTrue();
        }

        @Test
        @DisplayName("不相等的数组应该返回false")
        void unequalArraysReturnFalse() {
            byte[] a = {1, 2, 3, 4, 5};
            byte[] b = {1, 2, 3, 4, 6};

            assertThat(SecureBytes.constantTimeEquals(a, b)).isFalse();
        }

        @Test
        @DisplayName("长度不同应该返回false")
        void differentLengthReturnsFalse() {
            byte[] a = {1, 2, 3, 4, 5};
            byte[] b = {1, 2, 3, 4};

            assertThat(SecureBytes.constantTimeEquals(a, b)).isFalse();
        }

        @Test
        @DisplayName("两个null应该返回true")
        void bothNullReturnsTrue() {
            assertThat(SecureBytes.constantTimeEquals(null, null)).isTrue();
        }

        @Test
        @DisplayName("一个null应该返回false")
        void oneNullReturnsFalse() {
            byte[] a = {1, 2, 3};

            assertThat(SecureBytes.constantTimeEquals(a, null)).isFalse();
            assertThat(SecureBytes.constantTimeEquals(null, a)).isFalse();
        }

        @Test
        @DisplayName("空数组应该相等")
        void emptyArraysEqual() {
            byte[] a = new byte[0];
            byte[] b = new byte[0];

            assertThat(SecureBytes.constantTimeEquals(a, b)).isTrue();
        }

        @Test
        @DisplayName("第一个字节不同")
        void firstByteDifferent() {
            byte[] a = {1, 2, 3, 4, 5};
            byte[] b = {9, 2, 3, 4, 5};

            assertThat(SecureBytes.constantTimeEquals(a, b)).isFalse();
        }

        @Test
        @DisplayName("最后一个字节不同")
        void lastByteDifferent() {
            byte[] a = {1, 2, 3, 4, 5};
            byte[] b = {1, 2, 3, 4, 9};

            assertThat(SecureBytes.constantTimeEquals(a, b)).isFalse();
        }
    }

    @Nested
    @DisplayName("concat 方法测试")
    class ConcatTest {

        @Test
        @DisplayName("应该正确连接多个数组")
        void concatMultipleArrays() {
            byte[] a = {1, 2};
            byte[] b = {3, 4};
            byte[] c = {5, 6};

            byte[] result = SecureBytes.concat(a, b, c);

            assertThat(result).containsExactly((byte) 1, (byte) 2, (byte) 3, (byte) 4, (byte) 5, (byte) 6);
        }

        @Test
        @DisplayName("应该正确处理null数组")
        void concatWithNulls() {
            byte[] a = {1, 2};
            byte[] b = null;
            byte[] c = {3, 4};

            byte[] result = SecureBytes.concat(a, b, c);

            assertThat(result).containsExactly((byte) 1, (byte) 2, (byte) 3, (byte) 4);
        }

        @Test
        @DisplayName("单个数组应该返回副本")
        void concatSingleArray() {
            byte[] a = {1, 2, 3};

            byte[] result = SecureBytes.concat(a);

            assertThat(result).isEqualTo(a);
            assertThat(result).isNotSameAs(a);
        }

        @Test
        @DisplayName("空输入应该返回空数组")
        void concatEmpty() {
            byte[] result = SecureBytes.concat();

            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("空数组应该正确处理")
        void concatWithEmptyArrays() {
            byte[] a = {1, 2};
            byte[] b = new byte[0];
            byte[] c = {3, 4};

            byte[] result = SecureBytes.concat(a, b, c);

            assertThat(result).containsExactly((byte) 1, (byte) 2, (byte) 3, (byte) 4);
        }
    }

    @Nested
    @DisplayName("padLeft 方法测试")
    class PadLeftTest {

        @Test
        @DisplayName("应该正确左填充零")
        void padLeftWithZeros() {
            byte[] bytes = {1, 2, 3};

            byte[] result = SecureBytes.padLeft(bytes, 6);

            assertThat(result).containsExactly((byte) 0, (byte) 0, (byte) 0, (byte) 1, (byte) 2, (byte) 3);
        }

        @Test
        @DisplayName("长度已满足时应该返回副本")
        void padLeftAlreadySufficient() {
            byte[] bytes = {1, 2, 3};

            byte[] result = SecureBytes.padLeft(bytes, 3);

            assertThat(result).isEqualTo(bytes);
            assertThat(result).isNotSameAs(bytes);
        }

        @Test
        @DisplayName("原数组更长时应该截取最后几字节")
        void padLeftShorterLength() {
            byte[] bytes = {1, 2, 3, 4, 5};

            byte[] result = SecureBytes.padLeft(bytes, 3);

            // 截取最后3字节
            assertThat(result).containsExactly((byte) 3, (byte) 4, (byte) 5);
        }

        @Test
        @DisplayName("null应该返回全零数组")
        void padLeftNullReturnsZeros() {
            byte[] result = SecureBytes.padLeft(null, 5);

            assertThat(result).hasSize(5);
            assertThat(result).containsOnly((byte) 0);
        }

        @Test
        @DisplayName("填充到32字节（常用于区块链）")
        void padLeftTo32Bytes() {
            byte[] value = {0x01, 0x02};

            byte[] result = SecureBytes.padLeft(value, 32);

            assertThat(result).hasSize(32);
            assertThat(result[30]).isEqualTo((byte) 0x01);
            assertThat(result[31]).isEqualTo((byte) 0x02);
        }
    }

    @Nested
    @DisplayName("stripLeadingZeros 方法测试")
    class StripLeadingZerosTest {

        @Test
        @DisplayName("应该移除前导零")
        void stripLeadingZerosNormal() {
            byte[] bytes = {0, 0, 0, 1, 2, 3};

            byte[] result = SecureBytes.stripLeadingZeros(bytes);

            assertThat(result).containsExactly((byte) 1, (byte) 2, (byte) 3);
        }

        @Test
        @DisplayName("没有前导零应该返回相同内容")
        void stripLeadingZerosNone() {
            byte[] bytes = {1, 2, 3};

            byte[] result = SecureBytes.stripLeadingZeros(bytes);

            assertThat(result).containsExactly((byte) 1, (byte) 2, (byte) 3);
        }

        @Test
        @DisplayName("全零数组应该保留一个零")
        void stripLeadingZerosAllZeros() {
            byte[] bytes = {0, 0, 0, 0};

            byte[] result = SecureBytes.stripLeadingZeros(bytes);

            assertThat(result).containsExactly((byte) 0);
        }

        @Test
        @DisplayName("单个零应该保留")
        void stripLeadingZerosSingleZero() {
            byte[] bytes = {0};

            byte[] result = SecureBytes.stripLeadingZeros(bytes);

            assertThat(result).containsExactly((byte) 0);
        }

        @Test
        @DisplayName("null应该返回空数组")
        void stripLeadingZerosNull() {
            byte[] result = SecureBytes.stripLeadingZeros(null);

            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("空数组应该返回空数组")
        void stripLeadingZerosEmpty() {
            byte[] bytes = new byte[0];

            byte[] result = SecureBytes.stripLeadingZeros(bytes);

            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("BigInteger转换场景")
        void stripLeadingZerosForBigInteger() {
            // BigInteger.toByteArray() 经常在正数前添加 0x00
            byte[] bytes = {0x00, 0x7F, (byte) 0xFF};

            byte[] result = SecureBytes.stripLeadingZeros(bytes);

            assertThat(result).containsExactly((byte) 0x7F, (byte) 0xFF);
        }
    }
}