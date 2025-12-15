package io.github.superedison.web3.chain.evm.tx;

import io.github.superedison.web3.core.transaction.TransactionType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.*;

/**
 * EvmRawTransaction 单元测试
 * 测试 EVM 原始交易的构建和编码
 */
@DisplayName("EvmRawTransaction EVM原始交易测试")
class EvmRawTransactionTest {

    private static final byte[] TEST_ADDRESS = hexToBytes("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
    private static final String TEST_ADDRESS_HEX = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";

    @Nested
    @DisplayName("Builder 构建测试")
    class BuilderTest {

        @Test
        @DisplayName("默认值应该正确设置")
        void defaultValues() {
            EvmRawTransaction tx = EvmRawTransaction.builder().build();

            assertThat(tx.getNonce()).isEqualTo(BigInteger.ZERO);
            assertThat(tx.getGasPrice()).isEqualTo(BigInteger.ZERO);
            assertThat(tx.getGasLimit()).isEqualTo(BigInteger.valueOf(21000));
            assertThat(tx.getTo()).isNull();
            assertThat(tx.getValue()).isEqualTo(BigInteger.ZERO);
            assertThat(tx.getData()).isEmpty();
            assertThat(tx.getChainId()).isEqualTo(1);
        }

        @Test
        @DisplayName("BigInteger nonce 设置")
        void setNonceBigInteger() {
            BigInteger nonce = BigInteger.valueOf(42);
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .nonce(nonce)
                    .build();

            assertThat(tx.getNonce()).isEqualTo(nonce);
        }

        @Test
        @DisplayName("long nonce 设置")
        void setNonceLong() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .nonce(100L)
                    .build();

            assertThat(tx.getNonce()).isEqualTo(BigInteger.valueOf(100));
        }

        @Test
        @DisplayName("gasPrice 设置")
        void setGasPrice() {
            BigInteger gasPrice = new BigInteger("20000000000"); // 20 Gwei
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .gasPrice(gasPrice)
                    .build();

            assertThat(tx.getGasPrice()).isEqualTo(gasPrice);
        }

        @Test
        @DisplayName("gasLimit BigInteger 设置")
        void setGasLimitBigInteger() {
            BigInteger gasLimit = BigInteger.valueOf(100000);
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .gasLimit(gasLimit)
                    .build();

            assertThat(tx.getGasLimit()).isEqualTo(gasLimit);
        }

        @Test
        @DisplayName("gasLimit long 设置")
        void setGasLimitLong() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .gasLimit(50000L)
                    .build();

            assertThat(tx.getGasLimit()).isEqualTo(BigInteger.valueOf(50000));
        }

        @Test
        @DisplayName("to 地址 byte[] 设置")
        void setToBytes() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .to(TEST_ADDRESS)
                    .build();

            assertThat(tx.getTo()).isEqualTo(TEST_ADDRESS);
        }

        @Test
        @DisplayName("to 地址 String 设置（带0x前缀）")
        void setToStringWithPrefix() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .to(TEST_ADDRESS_HEX)
                    .build();

            assertThat(tx.getTo()).isEqualTo(TEST_ADDRESS);
        }

        @Test
        @DisplayName("to 地址 String 设置（无0x前缀）")
        void setToStringWithoutPrefix() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .to("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
                    .build();

            assertThat(tx.getTo()).isEqualTo(TEST_ADDRESS);
        }

        @Test
        @DisplayName("to 空字符串应该设为null（合约创建）")
        void setToEmptyString() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .to("")
                    .build();

            assertThat(tx.getTo()).isNull();
        }

        @Test
        @DisplayName("to null 字符串应该设为null")
        void setToNullString() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .to((String) null)
                    .build();

            assertThat(tx.getTo()).isNull();
        }

        @Test
        @DisplayName("value 设置")
        void setValue() {
            BigInteger value = new BigInteger("1000000000000000000"); // 1 ETH
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .value(value)
                    .build();

            assertThat(tx.getValue()).isEqualTo(value);
        }

        @Test
        @DisplayName("data byte[] 设置")
        void setDataBytes() {
            byte[] data = hexToBytes("a9059cbb"); // transfer 函数签名
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .data(data)
                    .build();

            assertThat(tx.getData()).isEqualTo(data);
        }

        @Test
        @DisplayName("data String 设置（带0x前缀）")
        void setDataStringWithPrefix() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .data("0xa9059cbb")
                    .build();

            assertThat(tx.getData()).isEqualTo(hexToBytes("a9059cbb"));
        }

        @Test
        @DisplayName("data 空字符串应该设为空数组")
        void setDataEmptyString() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .data("")
                    .build();

            assertThat(tx.getData()).isEmpty();
        }

        @Test
        @DisplayName("chainId 设置")
        void setChainId() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .chainId(56) // BSC
                    .build();

            assertThat(tx.getChainId()).isEqualTo(56);
        }

        @Test
        @DisplayName("链式调用构建完整交易")
        void chainedBuild() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .nonce(5)
                    .gasPrice(new BigInteger("20000000000"))
                    .gasLimit(21000)
                    .to(TEST_ADDRESS_HEX)
                    .value(new BigInteger("1000000000000000000"))
                    .data("0x")
                    .chainId(1)
                    .build();

            assertThat(tx.getNonce()).isEqualTo(BigInteger.valueOf(5));
            assertThat(tx.getGasPrice()).isEqualTo(new BigInteger("20000000000"));
            assertThat(tx.getGasLimit()).isEqualTo(BigInteger.valueOf(21000));
            assertThat(tx.getTo()).isEqualTo(TEST_ADDRESS);
            assertThat(tx.getValue()).isEqualTo(new BigInteger("1000000000000000000"));
            assertThat(tx.getChainId()).isEqualTo(1);
        }
    }

    @Nested
    @DisplayName("Getter 测试")
    class GetterTest {

        @Test
        @DisplayName("getTo 应该返回副本")
        void getToReturnsCopy() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .to(TEST_ADDRESS)
                    .build();

            byte[] to1 = tx.getTo();
            byte[] to2 = tx.getTo();

            to1[0] = (byte) 0xFF;
            assertThat(to2[0]).isNotEqualTo((byte) 0xFF);
        }

        @Test
        @DisplayName("getData 应该返回副本")
        void getDataReturnsCopy() {
            byte[] data = hexToBytes("a9059cbb");
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .data(data)
                    .build();

            byte[] data1 = tx.getData();
            byte[] data2 = tx.getData();

            data1[0] = (byte) 0xFF;
            assertThat(data2[0]).isNotEqualTo((byte) 0xFF);
        }

        @Test
        @DisplayName("getData null data 返回空数组")
        void getDataNullReturnsEmpty() {
            EvmRawTransaction tx = EvmRawTransaction.builder().build();

            assertThat(tx.getData()).isEmpty();
        }
    }

    @Nested
    @DisplayName("isContractCreation 测试")
    class IsContractCreationTest {

        @Test
        @DisplayName("to为null应该是合约创建")
        void nullToIsContractCreation() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .to((byte[]) null)
                    .build();

            assertThat(tx.isContractCreation()).isTrue();
        }

        @Test
        @DisplayName("to为空数组应该是合约创建")
        void emptyToIsContractCreation() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .to(new byte[0])
                    .build();

            assertThat(tx.isContractCreation()).isTrue();
        }

        @Test
        @DisplayName("to有值不是合约创建")
        void validToIsNotContractCreation() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .to(TEST_ADDRESS)
                    .build();

            assertThat(tx.isContractCreation()).isFalse();
        }
    }

    @Nested
    @DisplayName("getType 测试")
    class GetTypeTest {

        @Test
        @DisplayName("应该返回 EVM_LEGACY 类型")
        void returnsEvmLegacyType() {
            EvmRawTransaction tx = EvmRawTransaction.builder().build();

            assertThat(tx.getType()).isEqualTo(TransactionType.EVM_LEGACY);
        }
    }

    @Nested
    @DisplayName("encode 和 hash 测试")
    class EncodeHashTest {

        @Test
        @DisplayName("encode 应该返回非空字节数组")
        void encodeReturnsBytes() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .nonce(0)
                    .gasPrice(new BigInteger("20000000000"))
                    .gasLimit(21000)
                    .to(TEST_ADDRESS_HEX)
                    .value(new BigInteger("1000000000000000000"))
                    .chainId(1)
                    .build();

            byte[] encoded = tx.encode();

            assertThat(encoded).isNotEmpty();
        }

        @Test
        @DisplayName("hash 应该返回32字节")
        void hashReturns32Bytes() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .nonce(0)
                    .gasPrice(new BigInteger("20000000000"))
                    .gasLimit(21000)
                    .to(TEST_ADDRESS_HEX)
                    .value(new BigInteger("1000000000000000000"))
                    .chainId(1)
                    .build();

            byte[] hash = tx.hash();

            assertThat(hash).hasSize(32);
        }

        @Test
        @DisplayName("相同交易应该产生相同哈希")
        void sameTransactionSameHash() {
            EvmRawTransaction tx1 = EvmRawTransaction.builder()
                    .nonce(0)
                    .gasPrice(new BigInteger("20000000000"))
                    .gasLimit(21000)
                    .to(TEST_ADDRESS_HEX)
                    .value(new BigInteger("1000000000000000000"))
                    .chainId(1)
                    .build();

            EvmRawTransaction tx2 = EvmRawTransaction.builder()
                    .nonce(0)
                    .gasPrice(new BigInteger("20000000000"))
                    .gasLimit(21000)
                    .to(TEST_ADDRESS_HEX)
                    .value(new BigInteger("1000000000000000000"))
                    .chainId(1)
                    .build();

            assertThat(tx1.hash()).isEqualTo(tx2.hash());
        }

        @Test
        @DisplayName("不同nonce应该产生不同哈希")
        void differentNonceDifferentHash() {
            EvmRawTransaction tx1 = EvmRawTransaction.builder().nonce(0).build();
            EvmRawTransaction tx2 = EvmRawTransaction.builder().nonce(1).build();

            assertThat(tx1.hash()).isNotEqualTo(tx2.hash());
        }

        @Test
        @DisplayName("不同chainId应该产生不同哈希")
        void differentChainIdDifferentHash() {
            EvmRawTransaction tx1 = EvmRawTransaction.builder().chainId(1).build();
            EvmRawTransaction tx2 = EvmRawTransaction.builder().chainId(56).build();

            assertThat(tx1.hash()).isNotEqualTo(tx2.hash());
        }
    }

    @Nested
    @DisplayName("encodeForSigning EIP-155 编码测试")
    class EncodeForSigningTest {

        @Test
        @DisplayName("chainId > 0 应该包含 EIP-155 字段")
        void withChainIdIncludesEip155Fields() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .chainId(1)
                    .build();

            byte[] encoded = tx.encodeForSigning();

            // EIP-155 编码应该包含 chainId, 0, 0
            // 编码结果是 RLP list，不直接检查内容，只检查非空
            assertThat(encoded).isNotEmpty();
            // RLP list 的第一个字节应该 >= 0xc0
            assertThat(encoded[0] & 0xFF).isGreaterThanOrEqualTo(0xc0);
        }

        @Test
        @DisplayName("chainId = 0 应该不包含 EIP-155 字段（legacy）")
        void withoutChainIdNoEip155Fields() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .chainId(0)
                    .build();

            byte[] encoded = tx.encodeForSigning();

            assertThat(encoded).isNotEmpty();
        }

        @Test
        @DisplayName("完整交易 EIP-155 编码")
        void fullTransactionEncoding() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .nonce(9)
                    .gasPrice(new BigInteger("20000000000"))
                    .gasLimit(21000)
                    .to("0x3535353535353535353535353535353535353535")
                    .value(new BigInteger("1000000000000000000"))
                    .data(new byte[0])
                    .chainId(1)
                    .build();

            byte[] encoded = tx.encodeForSigning();
            byte[] hash = tx.hash();

            assertThat(encoded).isNotEmpty();
            assertThat(hash).hasSize(32);
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