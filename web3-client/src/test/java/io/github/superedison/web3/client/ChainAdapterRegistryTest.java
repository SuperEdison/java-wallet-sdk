package io.github.superedison.web3.client;

import io.github.superedison.web3.chain.ChainAdapter;
import io.github.superedison.web3.chain.ChainType;
import io.github.superedison.web3.chain.exception.UnsupportedChainException;
import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.transaction.RawTransaction;
import io.github.superedison.web3.core.transaction.SignedTransaction;
import io.github.superedison.web3.core.wallet.Address;
import io.github.superedison.web3.core.wallet.HDWallet;
import io.github.superedison.web3.core.wallet.Wallet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;

/**
 * ChainAdapterRegistry 单元测试
 */
@DisplayName("ChainAdapterRegistry 链适配器注册表测试")
class ChainAdapterRegistryTest {

    private ChainAdapterRegistry registry;
    private TestChainAdapter evmAdapter;
    private TestChainAdapter btcAdapter;

    @BeforeEach
    void setUp() {
        registry = ChainAdapterRegistry.create();
        evmAdapter = new TestChainAdapter(ChainType.EVM);
        btcAdapter = new TestChainAdapter(ChainType.BTC);
    }

    @Nested
    @DisplayName("create 静态方法测试")
    class CreateTest {

        @Test
        @DisplayName("应该创建空的注册表")
        void createEmptyRegistry() {
            ChainAdapterRegistry newRegistry = ChainAdapterRegistry.create();

            assertThat(newRegistry).isNotNull();
            assertThat(newRegistry.supports(ChainType.EVM)).isFalse();
        }
    }

    @Nested
    @DisplayName("register 方法测试")
    class RegisterTest {

        @Test
        @DisplayName("应该成功注册适配器")
        void registerAdapter() {
            registry.register(evmAdapter);

            assertThat(registry.supports(ChainType.EVM)).isTrue();
        }

        @Test
        @DisplayName("应该支持链式调用")
        void registerChaining() {
            registry.register(evmAdapter)
                    .register(btcAdapter);

            assertThat(registry.supports(ChainType.EVM)).isTrue();
            assertThat(registry.supports(ChainType.BTC)).isTrue();
        }

        @Test
        @DisplayName("重复注册应该覆盖旧适配器")
        void registerOverwrites() {
            TestChainAdapter adapter1 = new TestChainAdapter(ChainType.EVM);
            TestChainAdapter adapter2 = new TestChainAdapter(ChainType.EVM);

            registry.register(adapter1);
            registry.register(adapter2);

            assertThat(registry.get(ChainType.EVM)).isSameAs(adapter2);
        }
    }

    @Nested
    @DisplayName("get 方法测试")
    class GetTest {

        @Test
        @DisplayName("已注册的链类型应该返回适配器")
        void getRegisteredAdapter() {
            registry.register(evmAdapter);

            ChainAdapter retrieved = registry.get(ChainType.EVM);

            assertThat(retrieved).isSameAs(evmAdapter);
        }

        @Test
        @DisplayName("未注册的链类型应该抛出异常")
        void getUnregisteredThrows() {
            assertThatThrownBy(() -> registry.get(ChainType.EVM))
                    .isInstanceOf(UnsupportedChainException.class);
        }
    }

    @Nested
    @DisplayName("find 方法测试")
    class FindTest {

        @Test
        @DisplayName("已注册的链类型应该返回 Optional.of(adapter)")
        void findRegisteredAdapter() {
            registry.register(evmAdapter);

            Optional<ChainAdapter> result = registry.find(ChainType.EVM);

            assertThat(result).isPresent();
            assertThat(result.get()).isSameAs(evmAdapter);
        }

        @Test
        @DisplayName("未注册的链类型应该返回 Optional.empty()")
        void findUnregisteredReturnsEmpty() {
            Optional<ChainAdapter> result = registry.find(ChainType.EVM);

            assertThat(result).isEmpty();
        }
    }

    @Nested
    @DisplayName("supports 方法测试")
    class SupportsTest {

        @Test
        @DisplayName("已注册的链类型应该返回 true")
        void supportsRegistered() {
            registry.register(evmAdapter);

            assertThat(registry.supports(ChainType.EVM)).isTrue();
        }

        @Test
        @DisplayName("未注册的链类型应该返回 false")
        void supportsUnregistered() {
            assertThat(registry.supports(ChainType.EVM)).isFalse();
        }
    }

    @Nested
    @DisplayName("autoDiscover 方法测试")
    class AutoDiscoverTest {

        @Test
        @DisplayName("应该支持链式调用")
        void autoDiscoverChaining() {
            ChainAdapterRegistry result = registry.autoDiscover();

            assertThat(result).isSameAs(registry);
        }

        @Test
        @DisplayName("autoDiscover 不应该抛出异常（即使没有发现适配器）")
        void autoDiscoverNoException() {
            assertThatCode(() -> registry.autoDiscover())
                    .doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("withAutoDiscover 静态方法测试")
    class WithAutoDiscoverTest {

        @Test
        @DisplayName("应该创建新的注册表并自动发现")
        void createsAndAutoDiscovers() {
            ChainAdapterRegistry newRegistry = ChainAdapterRegistry.withAutoDiscover();

            assertThat(newRegistry).isNotNull();
        }
    }

    @Nested
    @DisplayName("并发访问测试")
    class ConcurrencyTest {

        @Test
        @DisplayName("并发注册和读取应该是线程安全的")
        void concurrentAccess() throws InterruptedException {
            int threadCount = 10;
            Thread[] threads = new Thread[threadCount];

            for (int i = 0; i < threadCount; i++) {
                final int index = i;
                threads[i] = new Thread(() -> {
                    // 注册
                    registry.register(new TestChainAdapter(ChainType.EVM));
                    // 读取
                    registry.supports(ChainType.EVM);
                    registry.find(ChainType.EVM);
                });
            }

            for (Thread thread : threads) {
                thread.start();
            }

            for (Thread thread : threads) {
                thread.join();
            }

            // 应该没有异常，且最终状态正确
            assertThat(registry.supports(ChainType.EVM)).isTrue();
        }
    }

    /**
     * 测试用的 ChainAdapter 实现
     */
    private static class TestChainAdapter implements ChainAdapter {

        private final ChainType chainType;

        TestChainAdapter(ChainType chainType) {
            this.chainType = chainType;
        }

        @Override
        public ChainType getChainType() {
            return chainType;
        }

        @Override
        public boolean isValidAddress(String address) {
            return false;
        }

        @Override
        public Address parseAddress(String address) {
            return null;
        }

        @Override
        public Address deriveAddress(byte[] publicKey) {
            return null;
        }

        @Override
        public HDWallet createHDWallet(int wordCount) {
            return null;
        }

        @Override
        public HDWallet fromMnemonic(List<String> mnemonic, String passphrase, String path) {
            return null;
        }

        @Override
        public Wallet fromPrivateKey(byte[] privateKey) {
            return null;
        }

        @Override
        public byte[] encodeTransaction(RawTransaction transaction) {
            return new byte[0];
        }

        @Override
        public byte[] hashTransaction(RawTransaction transaction) {
            return new byte[0];
        }

        @Override
        public byte[] encodeSignedTransaction(SignedTransaction transaction) {
            return new byte[0];
        }

        @Override
        public byte[] hashMessage(byte[] message) {
            return new byte[0];
        }

        @Override
        public Address recoverSigner(byte[] hash, Signature signature) {
            return null;
        }
    }
}