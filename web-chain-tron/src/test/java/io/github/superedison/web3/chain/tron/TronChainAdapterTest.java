package io.github.superedison.web3.chain.tron;

import io.github.superedison.web3.chain.ChainType;
import io.github.superedison.web3.chain.tron.address.TronAddress;
import io.github.superedison.web3.chain.tron.message.TronMessageSigner;
import io.github.superedison.web3.chain.tron.tx.TronRawTransaction;
import io.github.superedison.web3.chain.tron.tx.TronTransactionSigner;
import io.github.superedison.web3.chain.tron.tx.TronTransactionType;
import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.wallet.Address;
import io.github.superedison.web3.core.wallet.HDWallet;
import io.github.superedison.web3.core.wallet.Wallet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("TronChainAdapter TRON 链适配器测试")
class TronChainAdapterTest {

    private TronChainAdapter adapter;

    private static final byte[] TEST_PRIVATE_KEY = hexToBytes("0000000000000000000000000000000000000000000000000000000000000001");
    private static final String TEST_ADDRESS = "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC";
    private static final String TEST_ADDRESS_HEX = "417e5f4552091a69125d5dfcb7b8c2659029395bdf";

    private static final List<String> TEST_MNEMONIC = Arrays.asList(
            "leopard", "rotate", "tip", "rescue", "vessel", "rain",
            "argue", "detail", "music", "picture", "amused", "genuine"
    );
    // 第一个地址 (index 0): TVU9iSQSxvxWJYA1r8RnSCgJfziPLfRhDt
    // 第二个地址 (index 1): TBs9ghkcxEcw6unfJvXr2QHFpjiHSR9GTJ

    @BeforeEach
    void setUp() {
        adapter = new TronChainAdapter();
    }

    @Nested
    @DisplayName("getChainType 方法")
    class GetChainTypeTest {

        @Test
        @DisplayName("返回 TRON 类型")
        void returnsTron() {
            assertThat(adapter.getChainType()).isEqualTo(ChainType.TRON);
        }
    }

    @Nested
    @DisplayName("地址操作")
    class AddressOperationsTest {

        @Test
        @DisplayName("isValidAddress - 有效 Base58 地址")
        void isValidBase58Address() {
            assertThat(adapter.isValidAddress(TEST_ADDRESS)).isTrue();
        }

        @Test
        @DisplayName("isValidAddress - 有效十六进制地址")
        void isValidHexAddress() {
            assertThat(adapter.isValidAddress(TEST_ADDRESS_HEX)).isTrue();
        }

        @Test
        @DisplayName("isValidAddress - 无效地址")
        void isInvalidAddress() {
            assertThat(adapter.isValidAddress("invalid")).isFalse();
        }

        @Test
        @DisplayName("parseAddress - 解析 Base58 地址")
        void parseBase58Address() {
            Address address = adapter.parseAddress(TEST_ADDRESS);

            assertThat(address).isNotNull();
            assertThat(address.toBase58()).isEqualTo(TEST_ADDRESS);
        }

        @Test
        @DisplayName("parseAddress - 解析十六进制地址")
        void parseHexAddress() {
            Address address = adapter.parseAddress(TEST_ADDRESS_HEX);

            assertThat(address).isNotNull();
            assertThat(address.toBase58()).isEqualTo(TEST_ADDRESS);
        }

        @Test
        @DisplayName("deriveAddress - 从公钥派生")
        void deriveAddressFromPublicKey() {
            byte[] publicKey = hexToBytes("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
            Address address = adapter.deriveAddress(publicKey);

            assertThat(address.toBase58()).isEqualTo(TEST_ADDRESS);
        }
    }

    @Nested
    @DisplayName("钱包操作")
    class WalletOperationsTest {

        @Test
        @DisplayName("createHDWallet - 创建 24 词 HD 钱包")
        void createHDWallet24Words() {
            HDWallet wallet = adapter.createHDWallet(24);

            assertThat(wallet).isNotNull();
            assertThat(wallet.getMnemonic()).hasSize(24);
            assertThat(wallet.getDerivationPath()).isEqualTo(ChainType.TRON.getDefaultPath());
            assertThat(wallet.getAddress().toBase58()).startsWith("T");

            wallet.destroy();
        }

        @Test
        @DisplayName("createHDWallet - 创建 12 词 HD 钱包")
        void createHDWallet12Words() {
            HDWallet wallet = adapter.createHDWallet(12);

            assertThat(wallet).isNotNull();
            assertThat(wallet.getMnemonic()).hasSize(12);
            assertThat(wallet.getAddress().toBase58()).startsWith("T");

            wallet.destroy();
        }

        @Test
        @DisplayName("fromMnemonic - 从助记词恢复")
        void fromMnemonic() {
            HDWallet wallet = adapter.fromMnemonic(TEST_MNEMONIC, "", null);

            assertThat(wallet).isNotNull();
            assertThat(wallet.getMnemonic()).isEqualTo(TEST_MNEMONIC);
            assertThat(wallet.getDerivationPath()).isEqualTo(ChainType.TRON.getDefaultPath());
            // 验证第一个地址 (index 0)
            assertThat(wallet.getAddress().toBase58()).isEqualTo("TVU9iSQSxvxWJYA1r8RnSCgJfziPLfRhDt");

            wallet.destroy();
        }

        @Test
        @DisplayName("fromMnemonic - 自定义路径")
        void fromMnemonicCustomPath() {
            String customPath = "m/44'/195'/0'/0/1";
            HDWallet wallet = adapter.fromMnemonic(TEST_MNEMONIC, "", customPath);

            assertThat(wallet.getDerivationPath()).isEqualTo(customPath);
            // 验证第二个地址 (index 1)
            assertThat(wallet.getAddress().toBase58()).isEqualTo("TBs9ghkcxEcw6unfJvXr2QHFpjiHSR9GTJ");

            wallet.destroy();
        }

        @Test
        @DisplayName("fromPrivateKey - 从私钥创建")
        void fromPrivateKey() {
            Wallet wallet = adapter.fromPrivateKey(TEST_PRIVATE_KEY);

            assertThat(wallet).isNotNull();
            assertThat(wallet.getAddress().toBase58()).isEqualTo(TEST_ADDRESS);

            wallet.destroy();
        }
    }

    @Nested
    @DisplayName("交易操作")
    class TransactionOperationsTest {

        @Test
        @DisplayName("encodeTransaction - 编码交易")
        void encodeTransaction() {
            TronRawTransaction tx = createTestTransaction();
            byte[] encoded = adapter.encodeTransaction(tx);

            assertThat(encoded).isNotNull();
            assertThat(encoded.length).isGreaterThan(0);
        }

        @Test
        @DisplayName("hashTransaction - 计算交易哈希")
        void hashTransaction() {
            TronRawTransaction tx = createTestTransaction();
            byte[] hash = adapter.hashTransaction(tx);

            assertThat(hash).hasSize(32);
        }

        @Test
        @DisplayName("encodeSignedTransaction - 编码已签名交易")
        void encodeSignedTransaction() {
            TronRawTransaction tx = createTestTransaction();
            var signed = TronTransactionSigner.sign(tx, TEST_PRIVATE_KEY);

            byte[] encoded = adapter.encodeSignedTransaction(signed);

            assertThat(encoded).isNotNull();
            assertThat(encoded.length).isGreaterThan(0);
        }

        @Test
        @DisplayName("非 TRON 交易抛出异常")
        void nonTronTransactionThrows() {
            assertThatThrownBy(() -> adapter.encodeTransaction(null))
                    .isInstanceOf(Exception.class);
        }
    }

    @Nested
    @DisplayName("签名操作")
    class SignatureOperationsTest {

        @Test
        @DisplayName("hashMessage - 计算消息哈希")
        void hashMessage() {
            byte[] message = "Hello TRON".getBytes();
            byte[] hash = adapter.hashMessage(message);

            assertThat(hash).hasSize(32);
        }

        @Test
        @DisplayName("recoverSigner - 从签名恢复地址")
        void recoverSigner() {
            String message = "Hello TRON";
            byte[] hash = TronMessageSigner.hashMessage(message);
            Signature signature = TronMessageSigner.signHash(hash, TEST_PRIVATE_KEY);

            Address recovered = adapter.recoverSigner(hash, signature);

            assertThat(recovered.toBase58()).isEqualTo(TEST_ADDRESS);
        }

        @Test
        @DisplayName("recoverSigner - 无效哈希抛出异常")
        void invalidHashThrows() {
            Signature signature = TronMessageSigner.signMessage("test", TEST_PRIVATE_KEY);

            assertThatThrownBy(() -> adapter.recoverSigner(new byte[16], signature))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    private TronRawTransaction createTestTransaction() {
        return TronRawTransaction.builder()
                .type(TronTransactionType.TRANSFER_CONTRACT)
                .from(TEST_ADDRESS)
                .to("TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW")
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
