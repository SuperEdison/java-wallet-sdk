package io.github.superedison.web3.chain.evm.tx;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.assertj.core.api.Assertions.*;

/**
 * EvmTransactionSigner 单元测试
 * 测试 EVM 交易签名功能
 */
@DisplayName("EvmTransactionSigner EVM交易签名测试")
class EvmTransactionSignerTest {

    // 测试私钥（私钥=1，仅用于测试，切勿在生产中使用）
    private static final byte[] TEST_PRIVATE_KEY = hexToBytes(
            "0000000000000000000000000000000000000000000000000000000000000001");

    // 对应的地址（私钥=1对应的地址）
    private static final String EXPECTED_ADDRESS = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf";

    @Nested
    @DisplayName("sign 方法测试")
    class SignTest {

        @Test
        @DisplayName("应该成功签名简单转账交易")
        void signSimpleTransfer() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .nonce(0)
                    .gasPrice(new BigInteger("20000000000"))
                    .gasLimit(21000)
                    .to("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
                    .value(new BigInteger("1000000000000000000"))
                    .chainId(1)
                    .build();

            EvmSignedTransaction signed = EvmTransactionSigner.sign(tx, TEST_PRIVATE_KEY);

            assertThat(signed).isNotNull();
            assertThat(signed.isValid()).isTrue();
            assertThat(signed.getFrom()).isEqualToIgnoringCase(EXPECTED_ADDRESS);
        }

        @Test
        @DisplayName("签名后的交易应该包含有效签名")
        void signedTransactionHasValidSignature() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .nonce(5)
                    .gasPrice(new BigInteger("20000000000"))
                    .gasLimit(21000)
                    .to("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
                    .value(new BigInteger("100000000000000000"))
                    .chainId(1)
                    .build();

            EvmSignedTransaction signed = EvmTransactionSigner.sign(tx, TEST_PRIVATE_KEY);

            assertThat(signed.getSignature()).isNotNull();
            assertThat(signed.getSignature().bytes()).hasSize(65);
        }

        @Test
        @DisplayName("签名后的交易应该包含原始交易信息")
        void signedTransactionContainsRawTransaction() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .nonce(10)
                    .gasPrice(new BigInteger("30000000000"))
                    .gasLimit(50000)
                    .to("0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359")
                    .value(new BigInteger("500000000000000000"))
                    .chainId(1)
                    .build();

            EvmSignedTransaction signed = EvmTransactionSigner.sign(tx, TEST_PRIVATE_KEY);

            assertThat(signed.getRawTransaction()).isSameAs(tx);
        }

        @Test
        @DisplayName("不同nonce应该产生不同签名")
        void differentNonceDifferentSignature() {
            EvmRawTransaction tx1 = EvmRawTransaction.builder()
                    .nonce(0)
                    .to("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
                    .chainId(1)
                    .build();

            EvmRawTransaction tx2 = EvmRawTransaction.builder()
                    .nonce(1)
                    .to("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
                    .chainId(1)
                    .build();

            EvmSignedTransaction signed1 = EvmTransactionSigner.sign(tx1, TEST_PRIVATE_KEY);
            EvmSignedTransaction signed2 = EvmTransactionSigner.sign(tx2, TEST_PRIVATE_KEY);

            assertThat(signed1.encode()).isNotEqualTo(signed2.encode());
        }

        @Test
        @DisplayName("不同chainId应该产生不同签名")
        void differentChainIdDifferentSignature() {
            EvmRawTransaction txMainnet = EvmRawTransaction.builder()
                    .nonce(0)
                    .to("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
                    .chainId(1) // Mainnet
                    .build();

            EvmRawTransaction txBsc = EvmRawTransaction.builder()
                    .nonce(0)
                    .to("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
                    .chainId(56) // BSC
                    .build();

            EvmSignedTransaction signed1 = EvmTransactionSigner.sign(txMainnet, TEST_PRIVATE_KEY);
            EvmSignedTransaction signed2 = EvmTransactionSigner.sign(txBsc, TEST_PRIVATE_KEY);

            // 签名应该不同（因为 chainId 参与签名）
            assertThat(signed1.getSignature().bytes())
                    .isNotEqualTo(signed2.getSignature().bytes());
        }

        @Test
        @DisplayName("相同交易应该产生相同签名（确定性签名）")
        void sameTransactionSameSignature() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .nonce(0)
                    .gasPrice(new BigInteger("20000000000"))
                    .gasLimit(21000)
                    .to("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
                    .value(new BigInteger("1000000000000000000"))
                    .chainId(1)
                    .build();

            EvmSignedTransaction signed1 = EvmTransactionSigner.sign(tx, TEST_PRIVATE_KEY);
            EvmSignedTransaction signed2 = EvmTransactionSigner.sign(tx, TEST_PRIVATE_KEY);

            // 由于使用 RFC 6979 确定性 k，签名应该相同
            assertThat(signed1.encode()).isEqualTo(signed2.encode());
        }
    }

    @Nested
    @DisplayName("合约创建交易签名测试")
    class ContractCreationTest {

        @Test
        @DisplayName("应该成功签名合约创建交易")
        void signContractCreation() {
            byte[] contractBytecode = hexToBytes("6080604052348015600f57600080fd5b50");

            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .nonce(0)
                    .gasPrice(new BigInteger("20000000000"))
                    .gasLimit(1000000)
                    .to((byte[]) null) // 合约创建
                    .value(BigInteger.ZERO)
                    .data(contractBytecode)
                    .chainId(1)
                    .build();

            EvmSignedTransaction signed = EvmTransactionSigner.sign(tx, TEST_PRIVATE_KEY);

            assertThat(signed).isNotNull();
            assertThat(signed.isValid()).isTrue();
            assertThat(signed.getFrom()).isEqualToIgnoringCase(EXPECTED_ADDRESS);
        }
    }

    @Nested
    @DisplayName("合约调用交易签名测试")
    class ContractCallTest {

        @Test
        @DisplayName("应该成功签名 ERC-20 transfer 交易")
        void signErc20Transfer() {
            // ERC-20 transfer(address,uint256) 函数调用
            String functionSelector = "a9059cbb"; // transfer
            String recipientPadded = "000000000000000000000000fb6916095ca1df60bb79ce92ce3ea74c37c5d359";
            String amountPadded = "0000000000000000000000000000000000000000000000000de0b6b3a7640000"; // 1e18

            byte[] data = hexToBytes(functionSelector + recipientPadded + amountPadded);

            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .nonce(0)
                    .gasPrice(new BigInteger("20000000000"))
                    .gasLimit(60000)
                    .to("0xdAC17F958D2ee523a2206206994597C13D831ec7") // USDT
                    .value(BigInteger.ZERO)
                    .data(data)
                    .chainId(1)
                    .build();

            EvmSignedTransaction signed = EvmTransactionSigner.sign(tx, TEST_PRIVATE_KEY);

            assertThat(signed).isNotNull();
            assertThat(signed.isValid()).isTrue();
        }
    }

    @Nested
    @DisplayName("多链签名测试")
    class MultiChainTest {

        @Test
        @DisplayName("Ethereum Mainnet (chainId=1) 签名")
        void signEthereumMainnet() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .nonce(0)
                    .chainId(1)
                    .to("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
                    .build();

            EvmSignedTransaction signed = EvmTransactionSigner.sign(tx, TEST_PRIVATE_KEY);
            assertThat(signed.isValid()).isTrue();
        }

        @Test
        @DisplayName("BSC (chainId=56) 签名")
        void signBsc() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .nonce(0)
                    .chainId(56)
                    .to("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
                    .build();

            EvmSignedTransaction signed = EvmTransactionSigner.sign(tx, TEST_PRIVATE_KEY);
            assertThat(signed.isValid()).isTrue();
        }

        @Test
        @DisplayName("Polygon (chainId=137) 签名")
        void signPolygon() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .nonce(0)
                    .chainId(137)
                    .to("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
                    .build();

            EvmSignedTransaction signed = EvmTransactionSigner.sign(tx, TEST_PRIVATE_KEY);
            assertThat(signed.isValid()).isTrue();
        }

        @Test
        @DisplayName("Avalanche (chainId=43114) 签名")
        void signAvalanche() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .nonce(0)
                    .chainId(43114)
                    .to("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
                    .build();

            EvmSignedTransaction signed = EvmTransactionSigner.sign(tx, TEST_PRIVATE_KEY);
            assertThat(signed.isValid()).isTrue();
        }
    }

    @Nested
    @DisplayName("EvmSignedTransaction 输出测试")
    class SignedTransactionOutputTest {

        @Test
        @DisplayName("encode 应该返回非空字节数组")
        void encodeReturnsBytes() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .nonce(0)
                    .chainId(1)
                    .to("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
                    .build();

            EvmSignedTransaction signed = EvmTransactionSigner.sign(tx, TEST_PRIVATE_KEY);

            byte[] encoded = signed.encode();
            assertThat(encoded).isNotEmpty();
            // RLP list 的第一个字节应该 >= 0xc0
            assertThat(encoded[0] & 0xFF).isGreaterThanOrEqualTo(0xc0);
        }

        @Test
        @DisplayName("encodeHex 应该返回0x前缀的十六进制字符串")
        void encodeHexReturnsHexString() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .nonce(0)
                    .chainId(1)
                    .to("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
                    .build();

            EvmSignedTransaction signed = EvmTransactionSigner.sign(tx, TEST_PRIVATE_KEY);

            String hex = signed.encodeHex();
            assertThat(hex)
                    .startsWith("0x")
                    .matches("0x[0-9a-f]+");
        }

        @Test
        @DisplayName("getTransactionHash 应该返回32字节")
        void getTransactionHashReturns32Bytes() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .nonce(0)
                    .chainId(1)
                    .to("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
                    .build();

            EvmSignedTransaction signed = EvmTransactionSigner.sign(tx, TEST_PRIVATE_KEY);

            byte[] hash = signed.getTransactionHash();
            assertThat(hash).hasSize(32);
        }

        @Test
        @DisplayName("getTransactionHashHex 应该返回0x前缀的64字符十六进制")
        void getTransactionHashHexReturnsHex() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .nonce(0)
                    .chainId(1)
                    .to("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
                    .build();

            EvmSignedTransaction signed = EvmTransactionSigner.sign(tx, TEST_PRIVATE_KEY);

            String hashHex = signed.getTransactionHashHex();
            assertThat(hashHex)
                    .startsWith("0x")
                    .hasSize(66); // 0x + 64 hex chars
        }

        @Test
        @DisplayName("getTransactionHash 应该返回副本")
        void getTransactionHashReturnsCopy() {
            EvmRawTransaction tx = EvmRawTransaction.builder()
                    .nonce(0)
                    .chainId(1)
                    .to("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
                    .build();

            EvmSignedTransaction signed = EvmTransactionSigner.sign(tx, TEST_PRIVATE_KEY);

            byte[] hash1 = signed.getTransactionHash();
            byte[] hash2 = signed.getTransactionHash();

            hash1[0] = (byte) 0xFF;
            assertThat(hash2[0]).isNotEqualTo((byte) 0xFF);
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