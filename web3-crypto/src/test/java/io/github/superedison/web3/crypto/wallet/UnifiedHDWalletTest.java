package io.github.superedison.web3.crypto.wallet;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("UnifiedHDWallet 测试")
class UnifiedHDWalletTest {

    private static final String SECP_PATH = "m/44'/60'/0'/0/0";
    private static final String ED25519_PATH = "m/44'/501'/0'/0'";

    @Test
    @DisplayName("同一个 master seed 创建多个钱包应派生一致密钥")
    void sameMasterSeedShouldProduceSameKeysAcrossWallets() {
        byte[] seed = buildSeed();

        try (UnifiedHDWallet walletA = UnifiedHDWallet.fromSeed(seed);
             UnifiedHDWallet walletB = UnifiedHDWallet.fromSeed(seed)) {

            try (DerivedKey secpA = walletA.deriveSecp256k1(SECP_PATH);
                 DerivedKey secpB = walletB.deriveSecp256k1(SECP_PATH)) {
                assertThat(secpA.getPrivateKey()).isEqualTo(secpB.getPrivateKey());
                assertThat(secpA.getPublicKey(true)).isEqualTo(secpB.getPublicKey(true));
            }

            try (DerivedKey edA = walletA.deriveEd25519(ED25519_PATH);
                 DerivedKey edB = walletB.deriveEd25519(ED25519_PATH)) {
                assertThat(edA.getPrivateKey()).isEqualTo(edB.getPrivateKey());
                assertThat(edA.getPublicKey()).isEqualTo(edB.getPublicKey());
            }
        }
    }

    @Test
    @DisplayName("销毁一个钱包不应影响同 seed 的另一个钱包")
    void destroyingOneWalletShouldNotAffectAnotherWalletFromSameSeed() {
        byte[] seed = buildSeed();

        try (UnifiedHDWallet walletA = UnifiedHDWallet.fromSeed(seed);
             UnifiedHDWallet walletB = UnifiedHDWallet.fromSeed(seed)) {

            walletA.destroy();
            assertThat(walletA.isDestroyed()).isTrue();

            assertThatThrownBy(() -> walletA.deriveSecp256k1(SECP_PATH))
                    .isInstanceOf(IllegalStateException.class);

            try (DerivedKey keyB = walletB.deriveSecp256k1(SECP_PATH)) {
                assertThat(keyB.getPublicKey(true)).hasSize(33);
            }
        }
    }

    @Test
    @DisplayName("fromSeed 应复制输入 seed，外部修改不应污染钱包")
    void fromSeedShouldDefensivelyCopyInputSeed() {
        byte[] inputSeed = buildSeed();
        byte[] originalSeed = Arrays.copyOf(inputSeed, inputSeed.length);

        try (UnifiedHDWallet wallet = UnifiedHDWallet.fromSeed(inputSeed);
             UnifiedHDWallet expectedWallet = UnifiedHDWallet.fromSeed(originalSeed)) {

            Arrays.fill(inputSeed, (byte) 0);

            try (DerivedKey actual = wallet.deriveSecp256k1(SECP_PATH);
                 DerivedKey expected = expectedWallet.deriveSecp256k1(SECP_PATH)) {
                assertThat(actual.getPrivateKey()).isEqualTo(expected.getPrivateKey());
            }
        }
    }

    @Test
    @DisplayName("deriveRange 应保留最后一级硬化标记")
    void deriveRangeShouldPreserveHardenedSuffix() {
        byte[] seed = buildSeed();
        List<DerivedKey> keys = new ArrayList<>();

        try (UnifiedHDWallet wallet = UnifiedHDWallet.fromSeed(seed)) {
            keys = wallet.deriveRange("m/44'/501'/0'/0'", 0, 2, DerivationScheme.SLIP10_ED25519);

            assertThat(keys).hasSize(2);
            assertThat(keys.get(0).getPath()).isEqualTo("m/44'/501'/0'/0'");
            assertThat(keys.get(1).getPath()).isEqualTo("m/44'/501'/0'/1'");
            assertThat(keys.get(0).getPublicKey()).hasSize(32);
            assertThat(keys.get(1).getPublicKey()).hasSize(32);
        } finally {
            for (DerivedKey key : keys) {
                key.close();
            }
        }
    }

    @Test
    @DisplayName("并发创建多个同 seed 钱包应得到一致结果")
    void concurrentWalletCreationFromSameSeedShouldBeDeterministic() throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(8);
        try {
            List<Future<String>> futures = executor.invokeAll(
                    IntStream.range(0, 16)
                            .<java.util.concurrent.Callable<String>>mapToObj(i -> () -> {
                                byte[] seed = buildSeed();
                                try (UnifiedHDWallet wallet = UnifiedHDWallet.fromSeed(seed);
                                     DerivedKey key = wallet.deriveSecp256k1(SECP_PATH)) {
                                    return toHex(key.getPublicKey(true));
                                }
                            })
                            .toList()
            );

            Set<String> outputs = new HashSet<>();
            for (Future<String> future : futures) {
                outputs.add(future.get());
            }
            assertThat(outputs).hasSize(1);
        } finally {
            executor.shutdownNow();
        }
    }

    private static byte[] buildSeed() {
        byte[] seed = new byte[64];
        for (int i = 0; i < seed.length; i++) {
            seed[i] = (byte) i;
        }
        return seed;
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
}
