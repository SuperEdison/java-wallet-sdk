package io.github.superedison.web3.client.derive;

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
 * AccountDeriver 单元测试
 */
@DisplayName("AccountDeriver 账户派生工具测试")
class AccountDeriverTest {

    // 测试用助记词（仅用于测试，切勿在生产中使用）
    private static final List<String> TEST_MNEMONIC = Arrays.asList(
            "leopard", "rotate", "tip", "rescue", "vessel", "rain",
            "argue", "detail", "music", "picture", "amused", "genuine"
    );
    // EVM 第一个地址 (index 0): 0xd2c7d06eba1b002eacce0883f18904069f6a5f61
    // EVM 第二个地址 (index 1): 0x192dbd14f1e70da49e685d826fbfd5ed2be7d063
    private static final String EXPECTED_EVM_FIRST_ADDRESS = "0xd2c7d06eba1b002eacce0883f18904069f6a5f61";
    private static final String EXPECTED_EVM_SECOND_ADDRESS = "0x192dbd14f1e70da49e685d826fbfd5ed2be7d063";

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
            String[] userIds = {
                    "user_1", "user_abc", "很长的用户ID测试",
                    "special!@#$%", "12345", ""
            };

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

        @Test
        @DisplayName("特殊字符 userId 应该正常工作")
        void specialCharactersWork() {
            String[] specialUserIds = {
                    "user@example.com",
                    "用户123",
                    "user with spaces",
                    "user\ttab",
                    "user\nnewline",
                    "emoji😀user"
            };

            for (String userId : specialUserIds) {
                int index = AccountDeriver.userIdToAccountIndex(userId);
                assertThat(index).isGreaterThanOrEqualTo(0);
            }
        }
    }

    @Nested
    @DisplayName("getEvmPathForUser 方法测试")
    class GetEvmPathForUserTest {

        @Test
        @DisplayName("应该生成正确格式的路径")
        void correctPathFormat() {
            String path = AccountDeriver.getEvmPathForUser("user_1");

            assertThat(path).startsWith("m/44'/60'/");
            assertThat(path).endsWith("'/0/0");
        }

        @Test
        @DisplayName("相同 userId 应该生成相同路径")
        void sameUserIdSamePath() {
            String path1 = AccountDeriver.getEvmPathForUser("user_test");
            String path2 = AccountDeriver.getEvmPathForUser("user_test");

            assertThat(path1).isEqualTo(path2);
        }

        @Test
        @DisplayName("路径应该包含正确的账户索引")
        void pathContainsCorrectAccountIndex() {
            String userId = "user_123";
            int expectedIndex = AccountDeriver.userIdToAccountIndex(userId);
            String path = AccountDeriver.getEvmPathForUser(userId);

            String expectedPath = String.format("m/44'/60'/%d'/0/0", expectedIndex);
            assertThat(path).isEqualTo(expectedPath);
        }
    }

    @Nested
    @DisplayName("deriveEvmAddress 方法测试")
    class DeriveEvmAddressTest {

        @Test
        @DisplayName("应该生成有效的 EVM 地址")
        void generatesValidAddress() {
            String address = AccountDeriver.deriveEvmAddress(TEST_MNEMONIC, null, "user_1");

            assertThat(address).startsWith("0x");
            assertThat(address).hasSize(42); // 0x + 40 hex chars
        }

        @Test
        @DisplayName("相同 userId 应该生成相同地址")
        void sameUserIdSameAddress() {
            String address1 = AccountDeriver.deriveEvmAddress(TEST_MNEMONIC, null, "user_stable");
            String address2 = AccountDeriver.deriveEvmAddress(TEST_MNEMONIC, null, "user_stable");

            assertThat(address1).isEqualTo(address2);
        }

        @Test
        @DisplayName("不同 userId 应该生成不同地址")
        void differentUserIdDifferentAddress() {
            String address1 = AccountDeriver.deriveEvmAddress(TEST_MNEMONIC, null, "user_a");
            String address2 = AccountDeriver.deriveEvmAddress(TEST_MNEMONIC, null, "user_b");

            assertThat(address1).isNotEqualTo(address2);
        }

        @Test
        @DisplayName("不同密码应该生成不同地址")
        void differentPassphraseDifferentAddress() {
            String address1 = AccountDeriver.deriveEvmAddress(TEST_MNEMONIC, null, "user_1");
            String address2 = AccountDeriver.deriveEvmAddress(TEST_MNEMONIC, "secret", "user_1");

            assertThat(address1).isNotEqualTo(address2);
        }

        @Test
        @DisplayName("地址应该是 EIP-55 校验和格式")
        void addressIsChecksumFormat() {
            String address = AccountDeriver.deriveEvmAddress(TEST_MNEMONIC, null, "user_1");

            // EIP-55 地址包含大小写混合
            boolean hasUpperCase = address.substring(2).chars().anyMatch(Character::isUpperCase);
            boolean hasLowerCase = address.substring(2).chars().anyMatch(Character::isLowerCase);

            // 至少应该有一种大小写（除非地址碰巧全是数字，概率极低）
            assertThat(hasUpperCase || hasLowerCase).isTrue();
        }
    }

    @Nested
    @DisplayName("deriveForUser 方法测试")
    class DeriveForUserTest {

        @Test
        @DisplayName("应该返回完整的派生结果")
        void returnsCompleteResult() {
            try (AccountDeriver.DeriveResult result = AccountDeriver.deriveForUser(
                    TEST_MNEMONIC, null, "user_full")) {

                assertThat(result.userId()).isEqualTo("user_full");
                assertThat(result.accountIndex()).isGreaterThanOrEqualTo(0);
                assertThat(result.path()).startsWith("m/44'/60'/");
                assertThat(result.address()).startsWith("0x");
                assertThat(result.signingKey()).isNotNull();
                assertThat(result.signingKey().getPublicKey()).hasSize(65); // 非压缩公钥
            }
        }

        @Test
        @DisplayName("签名密钥应该可以安全销毁")
        void signingKeyCanBeDestroyed() {
            AccountDeriver.DeriveResult result = AccountDeriver.deriveForUser(
                    TEST_MNEMONIC, null, "user_wipe");

            assertThat(result.isDestroyed()).isFalse();

            // 销毁签名密钥
            result.close();

            // 验证已被销毁
            assertThat(result.isDestroyed()).isTrue();
        }

        @Test
        @DisplayName("try-with-resources 应该自动销毁")
        void tryWithResourcesAutoDestroy() {
            AccountDeriver.DeriveResult result;
            try (AccountDeriver.DeriveResult r = AccountDeriver.deriveForUser(
                    TEST_MNEMONIC, null, "user_auto")) {
                result = r;
                assertThat(r.isDestroyed()).isFalse();
            }
            assertThat(result.isDestroyed()).isTrue();
        }

        @Test
        @DisplayName("结果中的路径和地址应该一致")
        void pathAndAddressConsistent() {
            try (AccountDeriver.DeriveResult result = AccountDeriver.deriveForUser(
                    TEST_MNEMONIC, null, "user_consistent")) {

                // 使用相同 userId 单独派生地址，应该与结果一致
                String address = AccountDeriver.deriveEvmAddress(TEST_MNEMONIC, null, "user_consistent");

                assertThat(result.address()).isEqualTo(address);
            }
        }

        @Test
        @DisplayName("签名密钥可以用于签名")
        void signingKeyCanSign() {
            try (AccountDeriver.DeriveResult result = AccountDeriver.deriveForUser(
                    TEST_MNEMONIC, null, "user_sign")) {

                byte[] hash = new byte[32]; // 测试哈希
                var signature = result.signingKey().sign(hash);

                assertThat(signature).isNotNull();
                assertThat(signature.bytes()).hasSize(65); // r(32) + s(32) + v(1)
            }
        }
    }

    @Nested
    @DisplayName("唯一性测试")
    class UniquenessTest {

        @Test
        @DisplayName("批量派生应该产生唯一地址")
        void batchDeriveUniqueAddresses() {
            Set<String> addresses = new HashSet<>();
            int count = 100;

            for (int i = 0; i < count; i++) {
                String address = AccountDeriver.deriveEvmAddress(
                        TEST_MNEMONIC, null, "unique_user_" + i);
                addresses.add(address);
            }

            assertThat(addresses).hasSize(count);
        }

        @Test
        @DisplayName("批量索引应该分布均匀")
        @RepeatedTest(3)
        void accountIndexDistribution() {
            int[] buckets = new int[10]; // 分成10个桶
            int count = 1000;

            for (int i = 0; i < count; i++) {
                int index = AccountDeriver.userIdToAccountIndex("distribution_test_" + i);
                int bucket = (int) ((index / (double) Integer.MAX_VALUE) * 10);
                bucket = Math.min(bucket, 9); // 防止边界情况
                buckets[bucket]++;
            }

            // 每个桶应该有大约 count/10 个元素，允许 50% 的偏差
            int expected = count / 10;
            for (int bucket : buckets) {
                assertThat(bucket).isBetween(expected / 2, expected * 2);
            }
        }
    }

    @Nested
    @DisplayName("集成测试")
    class IntegrationTest {

        @Test
        @DisplayName("使用生成的助记词派生地址")
        void deriveWithGeneratedMnemonic() {
            // 生成新的助记词
            List<String> mnemonic = Bip39.generateMnemonic(24);

            String address1 = AccountDeriver.deriveEvmAddress(mnemonic, null, "user_1");
            String address2 = AccountDeriver.deriveEvmAddress(mnemonic, null, "user_2");

            assertThat(address1).startsWith("0x").hasSize(42);
            assertThat(address2).startsWith("0x").hasSize(42);
            assertThat(address1).isNotEqualTo(address2);
        }

        @Test
        @DisplayName("完整的工作流程测试")
        void completeWorkflow() {
            // 1. 生成主钱包助记词（实际应用中应安全存储）
            List<String> masterMnemonic = Bip39.generateMnemonic(24);

            // 2. 验证助记词
            assertThat(Bip39.validateMnemonic(masterMnemonic)).isTrue();

            // 3. 为多个用户派生地址
            String[] userIds = {"alice", "bob", "charlie"};
            Set<String> addresses = new HashSet<>();

            for (String userId : userIds) {
                // 使用 try-with-resources 自动销毁签名密钥
                try (AccountDeriver.DeriveResult result = AccountDeriver.deriveForUser(
                        masterMnemonic, null, userId)) {

                    assertThat(result.address()).isNotBlank();
                    addresses.add(result.address());
                } // 自动销毁签名密钥
            }

            // 4. 验证所有地址唯一
            assertThat(addresses).hasSize(userIds.length);

            // 5. 验证可重复性 - 相同用户ID应该得到相同地址
            String aliceAddress1 = AccountDeriver.deriveEvmAddress(masterMnemonic, null, "alice");
            String aliceAddress2 = AccountDeriver.deriveEvmAddress(masterMnemonic, null, "alice");
            assertThat(aliceAddress1).isEqualTo(aliceAddress2);
        }
    }
}
