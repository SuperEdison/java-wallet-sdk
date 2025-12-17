package io.github.superedison.web3.client.derive;

import io.github.superedison.web3.chain.btc.address.BtcAddressType;
import io.github.superedison.web3.chain.btc.address.BtcNetwork;
import io.github.superedison.web3.chain.spi.ChainType;
import io.github.superedison.web3.crypto.mnemonic.Bip39;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.RepeatedTest;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.*;

/**
 * AccountDeriver 多链账户派生测试
 */
@DisplayName("AccountDeriver 多链账户派生测试")
class AccountDeriverTest {
    final static String mnmenicString = """
                        leopard rotate tip rescue vessel rain argue detail music picture amused genuine
            """.trim();
    // 测试用助记词（仅用于测试，切勿在生产中使用）
    private static final List<String> TEST_MNEMONIC = List.of(mnmenicString.split(" "));

    @Nested
    @DisplayName("userIdToAccountIndex 方法测试")
    class UserIdToAccountIndexTest {

        @Test
        @DisplayName("应该为相同的 userId 返回相同的索引")
        void sameUserIdSameIndex() {
            String userId = "user_12345";

            int index1 = AccountDeriver.userIdToAccountIndex(userId);
            int index2 = AccountDeriver.userIdToAccountIndex(userId);

            assertThat(index1).isEqualTo(index2);
        }

        @Test
        @DisplayName("应该为不同的 userId 返回不同的索引")
        void differentUserIdDifferentIndex() {
            int index1 = AccountDeriver.userIdToAccountIndex("user_1");
            int index2 = AccountDeriver.userIdToAccountIndex("user_2");
            int index3 = AccountDeriver.userIdToAccountIndex("user_3");

            assertThat(index1).isNotEqualTo(index2);
            assertThat(index2).isNotEqualTo(index3);
            assertThat(index1).isNotEqualTo(index3);
        }

        @Test
        @DisplayName("索引应该在有效范围内 (0 到 2^31-1)")
        void indexInValidRange() {
            for (int i = 0; i < 100; i++) {
                String userId = "random_user_" + i;
                int index = AccountDeriver.userIdToAccountIndex(userId);
                assertThat(index).isGreaterThanOrEqualTo(0);
            }
        }

        @Test
        @DisplayName("空 userId 应该抛出异常")
        void nullUserIdThrows() {
            assertThatThrownBy(() -> AccountDeriver.userIdToAccountIndex(null))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("空字符串 userId 应该抛出异常")
        void emptyUserIdThrows() {
            assertThatThrownBy(() -> AccountDeriver.userIdToAccountIndex(""))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    @DisplayName("getPathForChain 方法测试")
    class GetPathForChainTest {

        @Test
        @DisplayName("EVM 路径应该正确")
        void evmPathCorrect() {
            String path = AccountDeriver.getPathForChain(ChainType.EVM, 0);
            assertThat(path).isEqualTo("m/44'/60'/0'/0/0");
        }

        @Test
        @DisplayName("TRON 路径应该正确")
        void tronPathCorrect() {
            String path = AccountDeriver.getPathForChain(ChainType.TRON, 5);
            assertThat(path).isEqualTo("m/44'/195'/5'/0/0");
        }

        @Test
        @DisplayName("Solana 路径应该使用硬化索引")
        void solanaPathHardened() {
            String path = AccountDeriver.getPathForChain(ChainType.SOL, 0);
            assertThat(path).isEqualTo("m/44'/501'/0'/0'");
        }
    }

    @Nested
    @DisplayName("getPathForBtcType 方法测试")
    class GetPathForBtcTypeTest {

        @Test
        @DisplayName("P2PKH 使用 purpose 44")
        void p2pkhPurpose44() {
            String path = AccountDeriver.getPathForBtcType(BtcAddressType.P2PKH, 0);
            assertThat(path).startsWith("m/44'/0'/");
        }

        @Test
        @DisplayName("P2SH-P2WPKH 使用 purpose 49")
        void p2shP2wpkhPurpose49() {
            String path = AccountDeriver.getPathForBtcType(BtcAddressType.P2SH_P2WPKH, 0);
            assertThat(path).startsWith("m/49'/0'/");
        }

        @Test
        @DisplayName("P2WPKH 使用 purpose 84")
        void p2wpkhPurpose84() {
            String path = AccountDeriver.getPathForBtcType(BtcAddressType.P2WPKH, 0);
            assertThat(path).startsWith("m/84'/0'/");
        }

        @Test
        @DisplayName("P2TR 使用 purpose 86")
        void p2trPurpose86() {
            String path = AccountDeriver.getPathForBtcType(BtcAddressType.P2TR, 0);
            assertThat(path).startsWith("m/86'/0'/");
        }
    }

    @Nested
    @DisplayName("EVM 地址派生测试")
    class EvmDeriveTest {

        @Test
        @DisplayName("应该生成有效的 EVM 地址")
        void generatesValidAddress() {
            try (AccountDeriver deriver = AccountDeriver.fromMnemonic(TEST_MNEMONIC)) {
                String address = deriver.deriveAddress("user_1", ChainType.EVM);

                assertThat(address).startsWith("0x");
                assertThat(address).hasSize(42);
            }
        }

        @Test
        @DisplayName("相同 userId 应该生成相同地址")
        void sameUserIdSameAddress() {
            try (AccountDeriver deriver = AccountDeriver.fromMnemonic(TEST_MNEMONIC)) {
                String address1 = deriver.deriveAddress("user_stable", ChainType.EVM);
                String address2 = deriver.deriveAddress("user_stable", ChainType.EVM);

                assertThat(address1).isEqualTo(address2);
            }
        }

        @Test
        @DisplayName("不同 userId 应该生成不同地址")
        void differentUserIdDifferentAddress() {
            try (AccountDeriver deriver = AccountDeriver.fromMnemonic(TEST_MNEMONIC)) {
                String address1 = deriver.deriveAddress("user_a", ChainType.EVM);
                String address2 = deriver.deriveAddress("user_b", ChainType.EVM);

                assertThat(address1).isNotEqualTo(address2);
            }
        }

        @Test
        @DisplayName("不同密码应该生成不同地址")
        void differentPassphraseDifferentAddress() {
            try (AccountDeriver deriver1 = AccountDeriver.fromMnemonic(TEST_MNEMONIC, "");
                 AccountDeriver deriver2 = AccountDeriver.fromMnemonic(TEST_MNEMONIC, "secret")) {
                String address1 = deriver1.deriveAddress("user_1", ChainType.EVM);
                String address2 = deriver2.deriveAddress("user_1", ChainType.EVM);

                assertThat(address1).isNotEqualTo(address2);
            }
        }
    }

    @Nested
    @DisplayName("deriveForUser 方法测试")
    class DeriveForUserTest {

        @Test
        @DisplayName("应该返回完整的派生结果")
        void returnsCompleteResult() {
            try (AccountDeriver deriver = AccountDeriver.fromMnemonic(TEST_MNEMONIC)) {
                try (ChainDeriveResult result = deriver.deriveForUser("user_full", ChainType.EVM)) {
                    assertThat(result.userId()).isEqualTo("user_full");
                    assertThat(result.accountIndex()).isGreaterThanOrEqualTo(0);
                    assertThat(result.path()).startsWith("m/44'/60'/");
                    assertThat(result.chainType()).isEqualTo(ChainType.EVM);
                    assertThat(result.address()).startsWith("0x");
                    assertThat(result.signingKey()).isNotNull();
                    assertThat(result.signingKey().getPublicKey()).hasSize(65);
                }
            }
        }

        @Test
        @DisplayName("签名密钥应该可以安全销毁")
        void signingKeyCanBeDestroyed() {
            try (AccountDeriver deriver = AccountDeriver.fromMnemonic(TEST_MNEMONIC)) {
                ChainDeriveResult result = deriver.deriveForUser("user_wipe", ChainType.EVM);

                assertThat(result.isDestroyed()).isFalse();
                result.close();
                assertThat(result.isDestroyed()).isTrue();
            }
        }

        @Test
        @DisplayName("签名密钥可以用于签名")
        void signingKeyCanSign() {
            try (AccountDeriver deriver = AccountDeriver.fromMnemonic(TEST_MNEMONIC)) {
                try (ChainDeriveResult result = deriver.deriveForUser("user_sign", ChainType.EVM)) {
                    byte[] hash = new byte[32];
                    var signature = result.signingKey().sign(hash);

                    assertThat(signature).isNotNull();
                    assertThat(signature.bytes()).hasSize(65);
                }
            }
        }
    }

    @Nested
    @DisplayName("多链派生测试")
    class MultiChainDeriveTest {

        @Test
        @DisplayName("TRON 地址以 T 开头")
        void tronAddressStartsWithT() {
            try (AccountDeriver deriver = AccountDeriver.fromMnemonic(TEST_MNEMONIC)) {
                String address = deriver.deriveAddress("user_1", ChainType.TRON);
                assertThat(address).startsWith("T");
            }
        }

        @Test
        @DisplayName("BTC P2WPKH 地址以 bc1q 开头")
        void btcSegwitAddress() {
            try (AccountDeriver deriver = AccountDeriver.fromMnemonic(TEST_MNEMONIC)) {
                DeriveOptions opts = DeriveOptions.builder()
                        .btcAddressType(BtcAddressType.P2WPKH)
                        .btcNetwork(BtcNetwork.MAINNET)
                        .build();
                String address = deriver.deriveAddress("user_1", ChainType.BTC, opts);
                assertThat(address).startsWith("bc1q");
            }
        }

        @Test
        @DisplayName("BTC P2PKH 地址以 1 开头")
        void btcLegacyAddress() {
            try (AccountDeriver deriver = AccountDeriver.fromMnemonic(TEST_MNEMONIC)) {
                DeriveOptions opts = DeriveOptions.builder()
                        .btcAddressType(BtcAddressType.P2PKH)
                        .btcNetwork(BtcNetwork.MAINNET)
                        .build();
                String address = deriver.deriveAddress("user_1", ChainType.BTC, opts);
                assertThat(address).startsWith("1");
            }
        }

        @Test
        @DisplayName("BTC Taproot 地址以 bc1p 开头")
        void btcTaprootAddress() {
            try (AccountDeriver deriver = AccountDeriver.fromMnemonic(TEST_MNEMONIC)) {
                DeriveOptions opts = DeriveOptions.builder()
                        .btcAddressType(BtcAddressType.P2TR)
                        .btcNetwork(BtcNetwork.MAINNET)
                        .build();
                String address = deriver.deriveAddress("user_1", ChainType.BTC, opts);
                assertThat(address).startsWith("bc1p");
            }
        }

        @Test
        @DisplayName("Solana 地址是 Base58 格式")
        void solanaAddressBase58() {
            try (AccountDeriver deriver = AccountDeriver.fromMnemonic(TEST_MNEMONIC)) {
                String address = deriver.deriveAddress("user_1", ChainType.SOL);
                assertThat(address).hasSize(44); // Base58 编码的 32 字节
                assertThat(address).matches("[1-9A-HJ-NP-Za-km-z]+"); // Base58 字符集
            }
        }

        @Test
        @DisplayName("Solana 地址派生向量验证")
        void solanaAddressTestVector() {
            try (AccountDeriver deriver = AccountDeriver.fromMnemonic(TEST_MNEMONIC)) {
                // 验证第一个地址 (account index 0)
                List<String> addresses = deriver.deriveAddresses(ChainType.SOL, 0, 2);

                System.out.println("Solana 地址 [0]: " + addresses.get(0));
                System.out.println("Solana 地址 [1]: " + addresses.get(1));

                assertThat(addresses.get(0)).isEqualTo("FFa2YFCS192tx4KAKpaLKPdbGmuTJs6wPT1WxYyYzo1W");
                assertThat(addresses.get(1)).isEqualTo("6W4rYZjVcxXVB72uAbuuXJBb7EZgRYqySxSM71jW3mMk");
            }
        }

        @Test
        @DisplayName("同一助记词为所有链派生不同地址")
        void sameUserDifferentChains() {
            try (AccountDeriver deriver = AccountDeriver.fromMnemonic(TEST_MNEMONIC)) {
                String userId = "user_multi";

                String evmAddr = deriver.deriveAddress(userId, ChainType.EVM);
                String tronAddr = deriver.deriveAddress(userId, ChainType.TRON);
                String btcAddr = deriver.deriveAddress(userId, ChainType.BTC);
                String solAddr = deriver.deriveAddress(userId, ChainType.SOL);

                // 所有地址都应该不同
                Set<String> addresses = Set.of(evmAddr, tronAddr, btcAddr, solAddr);
                assertThat(addresses).hasSize(4);
            }
        }
    }

    @Nested
    @DisplayName("批量派生测试")
    class BatchDeriveTest {

        @Test
        @DisplayName("批量派生地址应该唯一")
        void batchDeriveUniqueAddresses() {
            try (AccountDeriver deriver = AccountDeriver.fromMnemonic(TEST_MNEMONIC)) {
                List<String> addresses = deriver.deriveAddresses(ChainType.EVM, 0, 10);

                assertThat(addresses).hasSize(10);
                assertThat(new HashSet<>(addresses)).hasSize(10);
            }
        }

        @Test
        @DisplayName("批量派生结果应该包含签名密钥")
        void batchDeriveWithSigningKeys() {
            try (AccountDeriver deriver = AccountDeriver.fromMnemonic(TEST_MNEMONIC)) {
                List<ChainDeriveResult> results = deriver.deriveRange(ChainType.EVM, 0, 3);

                assertThat(results).hasSize(3);
                for (ChainDeriveResult result : results) {
                    assertThat(result.signingKey()).isNotNull();
                    result.close();
                }
            }
        }
    }

    @Nested
    @DisplayName("生命周期测试")
    class LifecycleTest {

        @Test
        @DisplayName("销毁后应该抛出异常")
        void destroyedThrowsException() {
            AccountDeriver deriver = AccountDeriver.fromMnemonic(TEST_MNEMONIC);
            deriver.destroy();

            assertThatThrownBy(() -> deriver.deriveAddress("user_1", ChainType.EVM))
                    .isInstanceOf(IllegalStateException.class);
        }

        @Test
        @DisplayName("try-with-resources 应该自动销毁")
        void tryWithResourcesAutoDestroy() {
            AccountDeriver deriver;
            try (AccountDeriver d = AccountDeriver.fromMnemonic(TEST_MNEMONIC)) {
                deriver = d;
                assertThat(d.isDestroyed()).isFalse();
            }
            assertThat(deriver.isDestroyed()).isTrue();
        }
    }

    @Nested
    @DisplayName("集成测试")
    class IntegrationTest {

        @Test
        @DisplayName("完整的多链工作流程")
        void completeMultiChainWorkflow() {
            // 生成助记词
            List<String> mnemonic = Bip39.generateMnemonic(24);
            assertThat(Bip39.validateMnemonic(mnemonic)).isTrue();

            try (AccountDeriver deriver = AccountDeriver.fromMnemonic(mnemonic)) {
                String[] userIds = {"alice", "bob", "charlie"};

                for (String userId : userIds) {
                    // 派生所有链地址
                    String evmAddr = deriver.deriveAddress(userId, ChainType.EVM);
                    String tronAddr = deriver.deriveAddress(userId, ChainType.TRON);

                    DeriveOptions btcOpts = DeriveOptions.builder()
                            .btcAddressType(BtcAddressType.P2WPKH)
                            .build();
                    String btcAddr = deriver.deriveAddress(userId, ChainType.BTC, btcOpts);

                    String solAddr = deriver.deriveAddress(userId, ChainType.SOL);

                    // 验证地址格式
                    assertThat(evmAddr).startsWith("0x").hasSize(42);
                    assertThat(tronAddr).startsWith("T");
                    assertThat(btcAddr).startsWith("bc1q");
                    assertThat(solAddr).matches("[1-9A-HJ-NP-Za-km-z]+");
                }

                // 验证可重复性
                String addr1 = deriver.deriveAddress("alice", ChainType.EVM);
                String addr2 = deriver.deriveAddress("alice", ChainType.EVM);
                assertThat(addr1).isEqualTo(addr2);
            }
        }

        @Test
        @DisplayName("使用签名密钥签名交易")
        void signTransactionWithDerivedKey() {
            try (AccountDeriver deriver = AccountDeriver.fromMnemonic(TEST_MNEMONIC)) {
                try (ChainDeriveResult result = deriver.deriveForUser("trader_1", ChainType.EVM)) {
                    // 模拟交易哈希
                    byte[] txHash = new byte[32];
                    for (int i = 0; i < 32; i++) txHash[i] = (byte) i;

                    // 签名
                    var signature = result.signingKey().sign(txHash);

                    assertThat(signature).isNotNull();
                    assertThat(signature.bytes()).hasSize(65);
                }
            }
        }
    }
}
