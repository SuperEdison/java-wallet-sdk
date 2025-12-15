package io.github.superedison.web3.chain.tron.tx;

import io.github.superedison.web3.chain.tron.address.TronAddress;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("TronTransactionSigner TRON 交易签名测试")
class TronTransactionSignerTest {

    private static final byte[] TEST_PRIVATE_KEY = hexToBytes("0000000000000000000000000000000000000000000000000000000000000001");
    private static final String TEST_ADDRESS = "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC";
    private static final String TO_ADDRESS = "TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW";

    @Nested
    @DisplayName("sign 方法")
    class SignTest {

        @Test
        @DisplayName("签名 TRX 转账交易")
        void signTransferTransaction() {
            TronRawTransaction tx = TronRawTransaction.builder()
                    .type(TronTransactionType.TRANSFER_CONTRACT)
                    .from(TEST_ADDRESS)
                    .to(TO_ADDRESS)
                    .amount(1_000_000) // 1 TRX
                    .refBlockBytes(new byte[]{0x00, 0x01})
                    .refBlockHash(new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07})
                    .expiration(System.currentTimeMillis() + 60_000)
                    .timestamp(System.currentTimeMillis())
                    .build();

            TronSignedTransaction signed = TronTransactionSigner.sign(tx, TEST_PRIVATE_KEY);

            assertThat(signed).isNotNull();
            assertThat(signed.getFrom()).isEqualTo(TEST_ADDRESS);
            assertThat(signed.getSignature()).isNotNull();
            assertThat(signed.getSignature().bytes()).hasSize(65);
        }

        @Test
        @DisplayName("签名包含发送者地址")
        void signedTransactionHasFrom() {
            TronRawTransaction tx = createTestTransaction();
            TronSignedTransaction signed = TronTransactionSigner.sign(tx, TEST_PRIVATE_KEY);

            assertThat(signed.getFrom()).isEqualTo(TEST_ADDRESS);
        }

        @Test
        @DisplayName("签名交易可编码")
        void signedTransactionCanEncode() {
            TronRawTransaction tx = createTestTransaction();
            TronSignedTransaction signed = TronTransactionSigner.sign(tx, TEST_PRIVATE_KEY);

            byte[] encoded = signed.encode();
            assertThat(encoded).isNotNull();
            assertThat(encoded.length).isGreaterThan(0);
        }

        @Test
        @DisplayName("签名交易有哈希")
        void signedTransactionHasHash() {
            TronRawTransaction tx = createTestTransaction();
            TronSignedTransaction signed = TronTransactionSigner.sign(tx, TEST_PRIVATE_KEY);

            byte[] hash = signed.getTransactionHash();
            assertThat(hash).hasSize(32);
        }

        @Test
        @DisplayName("相同交易相同签名（确定性）")
        void sameTransactionSameSignature() {
            long now = 1700000000000L;
            TronRawTransaction tx1 = TronRawTransaction.builder()
                    .type(TronTransactionType.TRANSFER_CONTRACT)
                    .from(TEST_ADDRESS)
                    .to(TO_ADDRESS)
                    .amount(1_000_000)
                    .refBlockBytes(new byte[]{0x00, 0x01})
                    .refBlockHash(new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07})
                    .expiration(now + 60_000)
                    .timestamp(now)
                    .build();

            TronRawTransaction tx2 = TronRawTransaction.builder()
                    .type(TronTransactionType.TRANSFER_CONTRACT)
                    .from(TEST_ADDRESS)
                    .to(TO_ADDRESS)
                    .amount(1_000_000)
                    .refBlockBytes(new byte[]{0x00, 0x01})
                    .refBlockHash(new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07})
                    .expiration(now + 60_000)
                    .timestamp(now)
                    .build();

            TronSignedTransaction signed1 = TronTransactionSigner.sign(tx1, TEST_PRIVATE_KEY);
            TronSignedTransaction signed2 = TronTransactionSigner.sign(tx2, TEST_PRIVATE_KEY);

            assertThat(signed1.getSignature().bytes()).isEqualTo(signed2.getSignature().bytes());
        }

        @Test
        @DisplayName("不同金额不同签名")
        void differentAmountDifferentSignature() {
            long now = 1700000000000L;
            TronRawTransaction tx1 = TronRawTransaction.builder()
                    .type(TronTransactionType.TRANSFER_CONTRACT)
                    .from(TEST_ADDRESS)
                    .to(TO_ADDRESS)
                    .amount(1_000_000)
                    .refBlockBytes(new byte[]{0x00, 0x01})
                    .refBlockHash(new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07})
                    .expiration(now + 60_000)
                    .timestamp(now)
                    .build();

            TronRawTransaction tx2 = TronRawTransaction.builder()
                    .type(TronTransactionType.TRANSFER_CONTRACT)
                    .from(TEST_ADDRESS)
                    .to(TO_ADDRESS)
                    .amount(2_000_000) // 不同金额
                    .refBlockBytes(new byte[]{0x00, 0x01})
                    .refBlockHash(new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07})
                    .expiration(now + 60_000)
                    .timestamp(now)
                    .build();

            TronSignedTransaction signed1 = TronTransactionSigner.sign(tx1, TEST_PRIVATE_KEY);
            TronSignedTransaction signed2 = TronTransactionSigner.sign(tx2, TEST_PRIVATE_KEY);

            assertThat(signed1.getSignature().bytes()).isNotEqualTo(signed2.getSignature().bytes());
        }

        @Test
        @DisplayName("空交易抛出异常")
        void nullTransactionThrows() {
            assertThatThrownBy(() -> TronTransactionSigner.sign(null, TEST_PRIVATE_KEY))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("无效私钥抛出异常")
        void invalidPrivateKeyThrows() {
            TronRawTransaction tx = createTestTransaction();

            assertThatThrownBy(() -> TronTransactionSigner.sign(tx, new byte[16]))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    @DisplayName("TRC-20 交易签名")
    class TRC20SignTest {

        @Test
        @DisplayName("签名 TRC-20 转账交易")
        void signTRC20Transfer() {
            // TRC-20 transfer 函数签名: transfer(address,uint256)
            // 函数选择器: a9059cbb
            String data = "a9059cbb" +
                    "000000000000000000000000" + "a614f803b6fd780986a42c78ec9c7f77e6ded13c" + // to address (去掉41前缀)
                    "0000000000000000000000000000000000000000000000000000000000000001";        // amount

            TronRawTransaction tx = TronRawTransaction.builder()
                    .type(TronTransactionType.TRIGGER_SMART_CONTRACT)
                    .from(TEST_ADDRESS)
                    .to("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t") // USDT 合约地址
                    .amount(0)
                    .data(data)
                    .feeLimit(10_000_000) // 10 TRX
                    .refBlockBytes(new byte[]{0x00, 0x01})
                    .refBlockHash(new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07})
                    .expiration(System.currentTimeMillis() + 60_000)
                    .timestamp(System.currentTimeMillis())
                    .build();

            TronSignedTransaction signed = TronTransactionSigner.sign(tx, TEST_PRIVATE_KEY);

            assertThat(signed).isNotNull();
            assertThat(signed.getFrom()).isEqualTo(TEST_ADDRESS);
            assertThat(signed.getRawTransaction().getType()).isEqualTo(io.github.superedison.web3.core.transaction.TransactionType.TRON_TRC20);
        }
    }

    private TronRawTransaction createTestTransaction() {
        return TronRawTransaction.builder()
                .type(TronTransactionType.TRANSFER_CONTRACT)
                .from(TEST_ADDRESS)
                .to(TO_ADDRESS)
                .amount(1_000_000)
                .refBlockBytes(new byte[]{0x00, 0x01})
                .refBlockHash(new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07})
                .expiration(System.currentTimeMillis() + 60_000)
                .timestamp(System.currentTimeMillis())
                .build();
    }

    private static byte[] hexToBytes(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }
}
