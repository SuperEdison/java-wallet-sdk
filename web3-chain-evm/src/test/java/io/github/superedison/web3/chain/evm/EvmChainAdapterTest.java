package io.github.superedison.web3.chain.evm;

import io.github.superedison.web3.chain.ChainType;
import io.github.superedison.web3.core.wallet.HDWallet;
import io.github.superedison.web3.core.wallet.Wallet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("EvmChainAdapter EVM 链适配器测试")
class EvmChainAdapterTest {

    private EvmChainAdapter adapter;

    private static final List<String> TEST_MNEMONIC = Arrays.asList(
            "leopard", "rotate", "tip", "rescue", "vessel", "rain",
            "argue", "detail", "music", "picture", "amused", "genuine"
    );
    // EVM 第一个地址 (index 0): 0xd2c7d06eba1b002eacce0883f18904069f6a5f61
    // EVM 第二个地址 (index 1): 0x192dbd14f1e70da49e685d826fbfd5ed2be7d063
    private static final String EXPECTED_FIRST_ADDRESS = "0xd2c7D06ebA1B002EaCce0883F18904069F6a5F61";
    private static final String EXPECTED_SECOND_ADDRESS = "0x192dbD14f1e70Da49E685d826fbFD5ed2be7d063";

    @BeforeEach
    void setUp() {
        adapter = new EvmChainAdapter();
    }

    @Nested
    @DisplayName("getChainType 方法")
    class GetChainTypeTest {

        @Test
        @DisplayName("返回 EVM 类型")
        void returnsEvm() {
            assertThat(adapter.getChainType()).isEqualTo(ChainType.EVM);
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
            assertThat(wallet.getDerivationPath()).isEqualTo(ChainType.EVM.getDefaultPath());
            assertThat(wallet.getAddress().toBase58()).startsWith("0x");

            wallet.destroy();
        }

        @Test
        @DisplayName("createHDWallet - 创建 12 词 HD 钱包")
        void createHDWallet12Words() {
            HDWallet wallet = adapter.createHDWallet(12);

            assertThat(wallet).isNotNull();
            assertThat(wallet.getMnemonic()).hasSize(12);
            assertThat(wallet.getAddress().toBase58()).startsWith("0x");

            wallet.destroy();
        }

        @Test
        @DisplayName("fromMnemonic - 从助记词恢复第一个地址")
        void fromMnemonicFirstAddress() {
            HDWallet wallet = adapter.fromMnemonic(TEST_MNEMONIC, "", null);

            assertThat(wallet).isNotNull();
            assertThat(wallet.getMnemonic()).isEqualTo(TEST_MNEMONIC);
            assertThat(wallet.getDerivationPath()).isEqualTo(ChainType.EVM.getDefaultPath());
            // 验证第一个地址 (index 0) - 忽略大小写比较 (EIP-55 checksum)
            assertThat(wallet.getAddress().toBase58().toLowerCase()).isEqualTo(EXPECTED_FIRST_ADDRESS.toLowerCase());

            wallet.destroy();
        }

        @Test
        @DisplayName("fromMnemonic - 从助记词恢复第二个地址")
        void fromMnemonicSecondAddress() {
            String customPath = "m/44'/60'/0'/0/1";
            HDWallet wallet = adapter.fromMnemonic(TEST_MNEMONIC, "", customPath);

            assertThat(wallet.getDerivationPath()).isEqualTo(customPath);
            // 验证第二个地址 (index 1) - 忽略大小写比较 (EIP-55 checksum)
            assertThat(wallet.getAddress().toBase58().toLowerCase()).isEqualTo(EXPECTED_SECOND_ADDRESS.toLowerCase());

            wallet.destroy();
        }

        @Test
        @DisplayName("派生子钱包验证地址")
        void deriveChildVerifyAddresses() {
            // 使用 m/44'/60'/0'/0 作为父路径，然后派生子地址
            String parentPath = "m/44'/60'/0'/0";
            HDWallet wallet = adapter.fromMnemonic(TEST_MNEMONIC, "", parentPath);

            var child0 = wallet.deriveChild(0);
            var child1 = wallet.deriveChild(1);

            assertThat(child0.getAddress()).isNotEqualTo(child1.getAddress());
            // 验证派生的地址 - 忽略大小写比较 (EIP-55 checksum)
            assertThat(child0.getAddress().toBase58().toLowerCase()).isEqualTo(EXPECTED_FIRST_ADDRESS.toLowerCase());
            assertThat(child1.getAddress().toBase58().toLowerCase()).isEqualTo(EXPECTED_SECOND_ADDRESS.toLowerCase());

            wallet.destroy();
        }

        @Test
        @DisplayName("批量派生地址验证")
        void deriveAddressesVerify() {
            String parentPath = "m/44'/60'/0'/0";
            HDWallet wallet = adapter.fromMnemonic(TEST_MNEMONIC, "", parentPath);

            var addresses = wallet.deriveAddresses(0, 5);

            assertThat(addresses).hasSize(5);
            // 验证前两个地址 - 忽略大小写比较 (EIP-55 checksum)
            assertThat(addresses.get(0).toBase58().toLowerCase()).isEqualTo(EXPECTED_FIRST_ADDRESS.toLowerCase());
            assertThat(addresses.get(1).toBase58().toLowerCase()).isEqualTo(EXPECTED_SECOND_ADDRESS.toLowerCase());

            // 确保每个地址都不同
            long uniqueCount = addresses.stream().map(a -> a.toBase58().toLowerCase()).distinct().count();
            assertThat(uniqueCount).isEqualTo(5);

            wallet.destroy();
        }
    }

    @Nested
    @DisplayName("地址操作")
    class AddressOperationsTest {

        @Test
        @DisplayName("isValidAddress - 有效地址")
        void isValidAddressValid() {
            assertThat(adapter.isValidAddress(EXPECTED_FIRST_ADDRESS)).isTrue();
            assertThat(adapter.isValidAddress(EXPECTED_SECOND_ADDRESS)).isTrue();
        }

        @Test
        @DisplayName("isValidAddress - 无效地址")
        void isValidAddressInvalid() {
            assertThat(adapter.isValidAddress("invalid")).isFalse();
            assertThat(adapter.isValidAddress("0x123")).isFalse();
        }

        @Test
        @DisplayName("parseAddress - 解析地址")
        void parseAddress() {
            var address = adapter.parseAddress(EXPECTED_FIRST_ADDRESS);

            assertThat(address).isNotNull();
            assertThat(address.toBase58().toLowerCase()).isEqualTo(EXPECTED_FIRST_ADDRESS.toLowerCase());
        }
    }
}
