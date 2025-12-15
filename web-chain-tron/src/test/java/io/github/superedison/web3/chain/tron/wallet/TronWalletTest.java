package io.github.superedison.web3.chain.tron.wallet;

import io.github.superedison.web3.chain.ChainType;
import io.github.superedison.web3.core.wallet.Address;
import io.github.superedison.web3.crypto.kdf.Bip32;
import io.github.superedison.web3.crypto.mnemonic.Bip39;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("TronWallet TRON 钱包测试")
class TronWalletTest {

    // 私钥 1
    private static final byte[] TEST_PRIVATE_KEY = hexToBytes("0000000000000000000000000000000000000000000000000000000000000001");
    private static final String EXPECTED_ADDRESS = "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC";

    // 标准测试助记词
    private static final List<String> TEST_MNEMONIC = Arrays.asList(
            "leopard", "rotate", "tip", "rescue", "vessel", "rain",
            "argue", "detail", "music", "picture", "amused", "genuine"
    );
    // 第一个地址 (index 0): TVU9iSQSxvxWJYA1r8RnSCgJfziPLfRhDt
    // 第二个地址 (index 1): TBs9ghkcxEcw6unfJvXr2QHFpjiHSR9GTJ
    private static final String EXPECTED_FIRST_ADDRESS = "TVU9iSQSxvxWJYA1r8RnSCgJfziPLfRhDt";
    private static final String EXPECTED_SECOND_ADDRESS = "TBs9ghkcxEcw6unfJvXr2QHFpjiHSR9GTJ";

    @Nested
    @DisplayName("TronWallet 基础钱包")
    class BasicWalletTest {

        @Test
        @DisplayName("从私钥创建钱包")
        void createFromPrivateKey() {
            TronWallet wallet = new TronWallet(null, TEST_PRIVATE_KEY, true);

            assertThat(wallet).isNotNull();
            assertThat(wallet.getAddress()).isNotNull();
            assertThat(wallet.getAddress().toBase58()).isEqualTo(EXPECTED_ADDRESS);
        }

        @Test
        @DisplayName("getId 返回地址")
        void getIdReturnsAddress() {
            TronWallet wallet = new TronWallet(null, TEST_PRIVATE_KEY, true);

            assertThat(wallet.getId()).isEqualTo(EXPECTED_ADDRESS);
        }

        @Test
        @DisplayName("自定义 ID")
        void customId() {
            TronWallet wallet = new TronWallet("my-wallet", TEST_PRIVATE_KEY, true);

            assertThat(wallet.getId()).isEqualTo("my-wallet");
        }

        @Test
        @DisplayName("getSigner 返回签名器")
        void getSignerReturnsSigner() {
            TronWallet wallet = new TronWallet(null, TEST_PRIVATE_KEY, true);

            assertThat(wallet.getSigner()).isNotNull();
            assertThat(wallet.getSigner().getAddress().toBase58()).isEqualTo(EXPECTED_ADDRESS);
        }

        @Test
        @DisplayName("getKeyHolder 返回密钥持有者")
        void getKeyHolderReturnsKeyHolder() {
            TronWallet wallet = new TronWallet(null, TEST_PRIVATE_KEY, true);

            assertThat(wallet.getKeyHolder()).isNotNull();
            assertThat(wallet.getKeyHolder().canExportPrivateKey()).isTrue();
        }

        @Test
        @DisplayName("无效私钥抛出异常")
        void invalidPrivateKeyThrows() {
            assertThatThrownBy(() -> new TronWallet(null, new byte[16], true))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("销毁钱包")
        void destroyWallet() {
            TronWallet wallet = new TronWallet(null, TEST_PRIVATE_KEY, true);
            wallet.destroy();

            assertThat(wallet.isDestroyed()).isTrue();
        }

        @Test
        @DisplayName("toString 不暴露私钥")
        void toStringRedacted() {
            TronWallet wallet = new TronWallet(null, TEST_PRIVATE_KEY, true);

            assertThat(wallet.toString()).contains("REDACTED");
            assertThat(wallet.toString()).doesNotContain("0000");
        }
    }

    @Nested
    @DisplayName("TronHDWallet HD 钱包")
    class HDWalletTest {

        @Test
        @DisplayName("从助记词创建 HD 钱包")
        void createFromMnemonic() {
            byte[] seed = Bip39.mnemonicToSeed(TEST_MNEMONIC, "");
            try (Bip32.ExtendedKey masterKey = Bip32.masterKeyFromSeed(seed)) {
                Bip32.ExtendedKey derivedKey = Bip32.derivePath(masterKey, ChainType.TRON.getDefaultPath());
                TronHDWallet wallet = new TronHDWallet(TEST_MNEMONIC, "", ChainType.TRON.getDefaultPath(), derivedKey, true);

                assertThat(wallet).isNotNull();
                assertThat(wallet.getMnemonic()).isEqualTo(TEST_MNEMONIC);
                assertThat(wallet.getDerivationPath()).isEqualTo(ChainType.TRON.getDefaultPath());
                // 验证第一个地址 (index 0)
                assertThat(wallet.getAddress().toBase58()).isEqualTo(EXPECTED_FIRST_ADDRESS);
            }
        }

        @Test
        @DisplayName("派生子钱包")
        void deriveChild() {
            byte[] seed = Bip39.mnemonicToSeed(TEST_MNEMONIC, "");
            try (Bip32.ExtendedKey masterKey = Bip32.masterKeyFromSeed(seed)) {
                Bip32.ExtendedKey derivedKey = Bip32.derivePath(masterKey, "m/44'/195'/0'/0");
                TronHDWallet wallet = new TronHDWallet(TEST_MNEMONIC, "", "m/44'/195'/0'/0", derivedKey, true);

                var child0 = wallet.deriveChild(0);
                var child1 = wallet.deriveChild(1);

                assertThat(child0.getAddress()).isNotEqualTo(child1.getAddress());
                // 验证派生的地址
                assertThat(child0.getAddress().toBase58()).isEqualTo(EXPECTED_FIRST_ADDRESS);
                assertThat(child1.getAddress().toBase58()).isEqualTo(EXPECTED_SECOND_ADDRESS);
            }
        }

        @Test
        @DisplayName("批量派生地址")
        void deriveAddresses() {
            byte[] seed = Bip39.mnemonicToSeed(TEST_MNEMONIC, "");
            try (Bip32.ExtendedKey masterKey = Bip32.masterKeyFromSeed(seed)) {
                Bip32.ExtendedKey derivedKey = Bip32.derivePath(masterKey, "m/44'/195'/0'/0");
                TronHDWallet wallet = new TronHDWallet(TEST_MNEMONIC, "", "m/44'/195'/0'/0", derivedKey, true);

                List<Address> addresses = wallet.deriveAddresses(0, 5);

                assertThat(addresses).hasSize(5);
                // 验证前两个地址
                assertThat(addresses.get(0).toBase58()).isEqualTo(EXPECTED_FIRST_ADDRESS);
                assertThat(addresses.get(1).toBase58()).isEqualTo(EXPECTED_SECOND_ADDRESS);

                // 确保每个地址都不同
                long uniqueCount = addresses.stream().map(Address::toBase58).distinct().count();
                assertThat(uniqueCount).isEqualTo(5);
            }
        }

        @Test
        @DisplayName("派生路径")
        void derivePath() {
            byte[] seed = Bip39.mnemonicToSeed(TEST_MNEMONIC, "");
            try (Bip32.ExtendedKey masterKey = Bip32.masterKeyFromSeed(seed)) {
                Bip32.ExtendedKey derivedKey = Bip32.derivePath(masterKey, ChainType.TRON.getDefaultPath());
                TronHDWallet wallet = new TronHDWallet(TEST_MNEMONIC, "", ChainType.TRON.getDefaultPath(), derivedKey, true);

                var derived = wallet.derivePath("m/44'/195'/0'/0/1");

                assertThat(derived.getDerivationPath()).isEqualTo("m/44'/195'/0'/0/1");
                // 验证第二个地址 (index 1)
                assertThat(derived.getAddress().toBase58()).isEqualTo(EXPECTED_SECOND_ADDRESS);
            }
        }

        @Test
        @DisplayName("销毁 HD 钱包")
        void destroyHDWallet() {
            byte[] seed = Bip39.mnemonicToSeed(TEST_MNEMONIC, "");
            try (Bip32.ExtendedKey masterKey = Bip32.masterKeyFromSeed(seed)) {
                Bip32.ExtendedKey derivedKey = Bip32.derivePath(masterKey, ChainType.TRON.getDefaultPath());
                TronHDWallet wallet = new TronHDWallet(TEST_MNEMONIC, "", ChainType.TRON.getDefaultPath(), derivedKey, true);

                wallet.destroy();

                assertThat(wallet.isDestroyed()).isTrue();
            }
        }

        @Test
        @DisplayName("toString 不暴露助记词")
        void toStringRedacted() {
            byte[] seed = Bip39.mnemonicToSeed(TEST_MNEMONIC, "");
            try (Bip32.ExtendedKey masterKey = Bip32.masterKeyFromSeed(seed)) {
                Bip32.ExtendedKey derivedKey = Bip32.derivePath(masterKey, ChainType.TRON.getDefaultPath());
                TronHDWallet wallet = new TronHDWallet(TEST_MNEMONIC, "", ChainType.TRON.getDefaultPath(), derivedKey, true);

                assertThat(wallet.toString()).contains("REDACTED");
                assertThat(wallet.toString()).doesNotContain("abandon");
            }
        }
    }

    private static byte[] hexToBytes(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }
}
