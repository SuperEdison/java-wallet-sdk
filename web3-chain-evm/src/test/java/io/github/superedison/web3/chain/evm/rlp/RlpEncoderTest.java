package io.github.superedison.web3.chain.evm.rlp;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;

import static org.assertj.core.api.Assertions.*;

/**
 * RlpEncoder 单元测试
 * 使用以太坊 RLP 规范的测试向量
 */
@DisplayName("RlpEncoder RLP编码测试")
class RlpEncoderTest {

    @Nested
    @DisplayName("encodeBytes 字节编码测试")
    class EncodeBytesTest {

        @Test
        @DisplayName("空字节数组应该编码为0x80")
        void encodeEmptyBytes() {
            byte[] result = RlpEncoder.encodeBytes(new byte[0]);

            assertThat(result).containsExactly((byte) 0x80);
        }

        @Test
        @DisplayName("null应该编码为0x80")
        void encodeNull() {
            byte[] result = RlpEncoder.encodeBytes(null);

            assertThat(result).containsExactly((byte) 0x80);
        }

        @Test
        @DisplayName("单字节 < 0x80 应该直接返回")
        void encodeSingleByteLessThan128() {
            byte[] result = RlpEncoder.encodeBytes(new byte[]{0x00});
            assertThat(result).containsExactly((byte) 0x00);

            result = RlpEncoder.encodeBytes(new byte[]{0x7F});
            assertThat(result).containsExactly((byte) 0x7F);
        }

        @Test
        @DisplayName("单字节 >= 0x80 应该加前缀0x81")
        void encodeSingleByteGreaterOrEqual128() {
            byte[] result = RlpEncoder.encodeBytes(new byte[]{(byte) 0x80});
            assertThat(result).containsExactly((byte) 0x81, (byte) 0x80);

            result = RlpEncoder.encodeBytes(new byte[]{(byte) 0xFF});
            assertThat(result).containsExactly((byte) 0x81, (byte) 0xFF);
        }

        @Test
        @DisplayName("长度 <= 55 字节应该正确编码")
        void encodeLengthLessThan56() {
            // 长度为2
            byte[] result = RlpEncoder.encodeBytes(new byte[]{0x01, 0x02});
            assertThat(result).containsExactly((byte) 0x82, (byte) 0x01, (byte) 0x02);

            // 长度为55
            byte[] data55 = new byte[55];
            for (int i = 0; i < 55; i++) data55[i] = (byte) i;
            result = RlpEncoder.encodeBytes(data55);
            assertThat(result[0]).isEqualTo((byte) (0x80 + 55));
            assertThat(result).hasSize(56);
        }

        @Test
        @DisplayName("长度 > 55 字节应该使用长格式")
        void encodeLengthGreaterThan55() {
            // 长度为56
            byte[] data56 = new byte[56];
            for (int i = 0; i < 56; i++) data56[i] = (byte) i;
            byte[] result = RlpEncoder.encodeBytes(data56);

            assertThat(result[0]).isEqualTo((byte) 0xb8); // 0xb7 + 1
            assertThat(result[1]).isEqualTo((byte) 56);   // 长度
            assertThat(result).hasSize(58); // 1 + 1 + 56
        }

        @Test
        @DisplayName("以太坊测试向量: 'dog'")
        void encodeStringDog() {
            byte[] dog = "dog".getBytes();
            byte[] result = RlpEncoder.encodeBytes(dog);

            // RLP("dog") = 0x83, 'd', 'o', 'g'
            assertThat(result).containsExactly((byte) 0x83, (byte) 'd', (byte) 'o', (byte) 'g');
        }

        @Test
        @DisplayName("长数据（256字节）编码")
        void encodeLongData() {
            byte[] data = new byte[256];
            for (int i = 0; i < 256; i++) data[i] = (byte) i;
            byte[] result = RlpEncoder.encodeBytes(data);

            // 0xb7 + 2 = 0xb9, 然后是两字节长度 0x01 0x00
            assertThat(result[0]).isEqualTo((byte) 0xb9);
            assertThat(result[1]).isEqualTo((byte) 0x01);
            assertThat(result[2]).isEqualTo((byte) 0x00);
            assertThat(result).hasSize(259); // 1 + 2 + 256
        }
    }

    @Nested
    @DisplayName("encodeBigInteger BigInteger编码测试")
    class EncodeBigIntegerTest {

        @Test
        @DisplayName("零应该编码为0x80（空字节）")
        void encodeZero() {
            byte[] result = RlpEncoder.encodeBigInteger(BigInteger.ZERO);

            assertThat(result).containsExactly((byte) 0x80);
        }

        @Test
        @DisplayName("null应该编码为0x80")
        void encodeNullBigInteger() {
            byte[] result = RlpEncoder.encodeBigInteger(null);

            assertThat(result).containsExactly((byte) 0x80);
        }

        @Test
        @DisplayName("小整数应该正确编码")
        void encodeSmallIntegers() {
            // 1 -> 0x01
            assertThat(RlpEncoder.encodeBigInteger(BigInteger.ONE))
                    .containsExactly((byte) 0x01);

            // 127 -> 0x7f
            assertThat(RlpEncoder.encodeBigInteger(BigInteger.valueOf(127)))
                    .containsExactly((byte) 0x7f);

            // 128 -> 0x81 0x80
            assertThat(RlpEncoder.encodeBigInteger(BigInteger.valueOf(128)))
                    .containsExactly((byte) 0x81, (byte) 0x80);
        }

        @Test
        @DisplayName("大整数应该正确编码")
        void encodeLargeIntegers() {
            // 256 -> 0x82 0x01 0x00
            assertThat(RlpEncoder.encodeBigInteger(BigInteger.valueOf(256)))
                    .containsExactly((byte) 0x82, (byte) 0x01, (byte) 0x00);

            // 1024 -> 0x82 0x04 0x00
            assertThat(RlpEncoder.encodeBigInteger(BigInteger.valueOf(1024)))
                    .containsExactly((byte) 0x82, (byte) 0x04, (byte) 0x00);
        }

        @Test
        @DisplayName("BigInteger前导零应该被移除")
        void removeLeadingZeros() {
            // BigInteger(127).toByteArray() 返回 [0x7f]
            // BigInteger(128).toByteArray() 返回 [0x00, 0x80] - 有前导零
            BigInteger val = BigInteger.valueOf(128);
            byte[] result = RlpEncoder.encodeBigInteger(val);

            // 应该是 0x81 0x80，而不是 0x82 0x00 0x80
            assertThat(result).containsExactly((byte) 0x81, (byte) 0x80);
        }

        @Test
        @DisplayName("以太坊 gas price 示例")
        void encodeGasPrice() {
            // 20 Gwei = 20 * 10^9 = 20000000000
            BigInteger gasPrice = new BigInteger("20000000000");
            byte[] result = RlpEncoder.encodeBigInteger(gasPrice);

            // 验证可以正确编码
            assertThat(result).isNotEmpty();
            assertThat(result[0] & 0xFF).isGreaterThanOrEqualTo(0x80);
        }
    }

    @Nested
    @DisplayName("encodeLong long编码测试")
    class EncodeLongTest {

        @Test
        @DisplayName("零应该编码为0x80")
        void encodeZeroLong() {
            byte[] result = RlpEncoder.encodeLong(0);

            assertThat(result).containsExactly((byte) 0x80);
        }

        @Test
        @DisplayName("正整数应该正确编码")
        void encodePositiveLong() {
            assertThat(RlpEncoder.encodeLong(1))
                    .containsExactly((byte) 0x01);

            assertThat(RlpEncoder.encodeLong(127))
                    .containsExactly((byte) 0x7f);

            assertThat(RlpEncoder.encodeLong(128))
                    .containsExactly((byte) 0x81, (byte) 0x80);

            assertThat(RlpEncoder.encodeLong(21000)) // 标准转账 gas limit
                    .isNotEmpty();
        }

        @Test
        @DisplayName("chain ID 应该正确编码")
        void encodeChainId() {
            // Ethereum Mainnet (1)
            assertThat(RlpEncoder.encodeLong(1))
                    .containsExactly((byte) 0x01);

            // BSC (56)
            assertThat(RlpEncoder.encodeLong(56))
                    .containsExactly((byte) 0x38);

            // Polygon (137)
            assertThat(RlpEncoder.encodeLong(137))
                    .containsExactly((byte) 0x81, (byte) 0x89);
        }
    }

    @Nested
    @DisplayName("encodeList 列表编码测试")
    class EncodeListTest {

        @Test
        @DisplayName("空列表应该编码为0xc0")
        void encodeEmptyList() {
            byte[] result = RlpEncoder.encodeList(List.of());

            assertThat(result).containsExactly((byte) 0xc0);
        }

        @Test
        @DisplayName("以太坊测试向量: ['cat', 'dog']")
        void encodeCatDogList() {
            byte[] cat = RlpEncoder.encodeBytes("cat".getBytes());
            byte[] dog = RlpEncoder.encodeBytes("dog".getBytes());

            byte[] result = RlpEncoder.encodeList(List.of(cat, dog));

            // RLP(['cat', 'dog']) = [0xc8, 0x83, 'c', 'a', 't', 0x83, 'd', 'o', 'g']
            assertThat(result[0]).isEqualTo((byte) 0xc8);
            assertThat(result).hasSize(9);
        }

        @Test
        @DisplayName("可变参数版本应该工作")
        void encodeListVarargs() {
            byte[] a = RlpEncoder.encodeBytes(new byte[]{0x01});
            byte[] b = RlpEncoder.encodeBytes(new byte[]{0x02});

            byte[] result = RlpEncoder.encodeList(a, b);

            assertThat(result).isNotEmpty();
            assertThat(result[0] & 0xFF).isGreaterThanOrEqualTo(0xc0);
        }

        @Test
        @DisplayName("嵌套列表应该正确编码")
        void encodeNestedList() {
            // [[]]
            byte[] innerEmpty = RlpEncoder.encodeList(List.of());
            byte[] result = RlpEncoder.encodeList(List.of(innerEmpty));

            // [[]] = 0xc1 0xc0
            assertThat(result).containsExactly((byte) 0xc1, (byte) 0xc0);
        }

        @Test
        @DisplayName("长列表应该使用长格式")
        void encodeLongList() {
            // 创建一个总长度 > 55 的列表
            byte[][] elements = new byte[20][];
            for (int i = 0; i < 20; i++) {
                elements[i] = RlpEncoder.encodeBytes(("item" + i).getBytes());
            }

            byte[] result = RlpEncoder.encodeList(List.of(elements));

            // 第一个字节应该 > 0xf7
            assertThat(result[0] & 0xFF).isGreaterThan(0xf7);
        }
    }

    @Nested
    @DisplayName("encodeAddress 地址编码测试")
    class EncodeAddressTest {

        @Test
        @DisplayName("有效的20字节地址应该正确编码")
        void encodeValidAddress() {
            byte[] address = hexToBytes("0000000000000000000000000000000000000000");
            byte[] result = RlpEncoder.encodeAddress(address);

            // 20 字节地址 -> 0x94 + 20字节
            assertThat(result[0]).isEqualTo((byte) 0x94);
            assertThat(result).hasSize(21);
        }

        @Test
        @DisplayName("空地址应该编码为0x80")
        void encodeEmptyAddress() {
            byte[] result = RlpEncoder.encodeAddress(null);
            assertThat(result).containsExactly((byte) 0x80);

            result = RlpEncoder.encodeAddress(new byte[0]);
            assertThat(result).containsExactly((byte) 0x80);
        }

        @Test
        @DisplayName("无效长度地址应该抛出异常")
        void invalidLengthThrows() {
            assertThatThrownBy(() -> RlpEncoder.encodeAddress(new byte[19]))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("20 bytes");

            assertThatThrownBy(() -> RlpEncoder.encodeAddress(new byte[21]))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    @DisplayName("交易编码集成测试")
    class TransactionEncodingTest {

        @Test
        @DisplayName("简单ETH转账交易RLP编码")
        void encodeSimpleTransfer() {
            // 模拟一个简单的 ETH 转账交易
            BigInteger nonce = BigInteger.ZERO;
            BigInteger gasPrice = new BigInteger("20000000000"); // 20 Gwei
            BigInteger gasLimit = BigInteger.valueOf(21000);
            byte[] to = hexToBytes("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
            BigInteger value = new BigInteger("1000000000000000000"); // 1 ETH
            byte[] data = new byte[0];
            long chainId = 1;

            // 编码各字段
            byte[] encodedNonce = RlpEncoder.encodeBigInteger(nonce);
            byte[] encodedGasPrice = RlpEncoder.encodeBigInteger(gasPrice);
            byte[] encodedGasLimit = RlpEncoder.encodeBigInteger(gasLimit);
            byte[] encodedTo = RlpEncoder.encodeAddress(to);
            byte[] encodedValue = RlpEncoder.encodeBigInteger(value);
            byte[] encodedData = RlpEncoder.encodeBytes(data);
            byte[] encodedChainId = RlpEncoder.encodeLong(chainId);
            byte[] encodedZero1 = RlpEncoder.encodeBigInteger(BigInteger.ZERO);
            byte[] encodedZero2 = RlpEncoder.encodeBigInteger(BigInteger.ZERO);

            // EIP-155 编码
            byte[] encoded = RlpEncoder.encodeList(
                    encodedNonce, encodedGasPrice, encodedGasLimit,
                    encodedTo, encodedValue, encodedData,
                    encodedChainId, encodedZero1, encodedZero2);

            assertThat(encoded).isNotEmpty();
            assertThat(encoded[0] & 0xFF).isGreaterThanOrEqualTo(0xc0);
        }

        @Test
        @DisplayName("合约创建交易（to为空）")
        void encodeContractCreation() {
            BigInteger nonce = BigInteger.ONE;
            BigInteger gasPrice = new BigInteger("20000000000");
            BigInteger gasLimit = BigInteger.valueOf(1000000);
            byte[] to = null; // 合约创建
            BigInteger value = BigInteger.ZERO;
            byte[] data = hexToBytes("6080604052"); // 合约字节码片段

            byte[] encoded = RlpEncoder.encodeList(
                    RlpEncoder.encodeBigInteger(nonce),
                    RlpEncoder.encodeBigInteger(gasPrice),
                    RlpEncoder.encodeBigInteger(gasLimit),
                    RlpEncoder.encodeAddress(to),
                    RlpEncoder.encodeBigInteger(value),
                    RlpEncoder.encodeBytes(data));

            assertThat(encoded).isNotEmpty();
        }
    }

    // 辅助方法
    private static byte[] hexToBytes(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }
}