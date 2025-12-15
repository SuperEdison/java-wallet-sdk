package io.github.superedison.web3.client;

import io.github.superedison.web3.chain.ChainAdapter;
import io.github.superedison.web3.chain.ChainType;
import io.github.superedison.web3.chain.exception.UnsupportedChainException;
import io.github.superedison.web3.core.transaction.RawTransaction;
import io.github.superedison.web3.core.transaction.SignedTransaction;
import io.github.superedison.web3.core.wallet.Address;
import io.github.superedison.web3.core.wallet.HDWallet;
import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.wallet.Wallet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.*;

/**
 * Web3Client 单元测试
 */
@DisplayName("Web3Client SDK客户端测试")
class Web3ClientTest {

    private Web3Client client;
    private TestChainAdapter evmAdapter;

    @BeforeEach
    void setUp() {
        evmAdapter = new TestChainAdapter(ChainType.EVM);
        client = Web3Client.builder()
                .register(evmAdapter)
                .build();
    }

    @Nested
    @DisplayName("Builder 测试")
    class BuilderTest {

        @Test
        @DisplayName("空 Builder 应该创建有效的客户端")
        void emptyBuilderCreatesClient() {
            Web3Client emptyClient = Web3Client.builder().build();

            assertThat(emptyClient).isNotNull();
        }

        @Test
        @DisplayName("register 应该注册适配器")
        void registerAddsAdapter() {
            Web3Client newClient = Web3Client.builder()
                    .register(evmAdapter)
                    .build();

            assertThat(newClient.supports(ChainType.EVM)).isTrue();
        }

        @Test
        @DisplayName("链式 register 应该注册多个适配器")
        void chainedRegister() {
            TestChainAdapter btcAdapter = new TestChainAdapter(ChainType.BTC);

            Web3Client newClient = Web3Client.builder()
                    .register(evmAdapter)
                    .register(btcAdapter)
                    .build();

            assertThat(newClient.supports(ChainType.EVM)).isTrue();
            assertThat(newClient.supports(ChainType.BTC)).isTrue();
        }

        @Test
        @DisplayName("autoDiscover 应该调用注册表的自动发现")
        void autoDiscoverCalled() {
            Web3Client newClient = Web3Client.builder()
                    .autoDiscover()
                    .build();

            assertThat(newClient).isNotNull();
        }

        @Test
        @DisplayName("registry 应该使用指定的注册表")
        void customRegistry() {
            ChainAdapterRegistry customRegistry = ChainAdapterRegistry.create();
            customRegistry.register(evmAdapter);

            Web3Client newClient = Web3Client.builder()
                    .registry(customRegistry)
                    .build();

            assertThat(newClient.supports(ChainType.EVM)).isTrue();
        }
    }

    @Nested
    @DisplayName("supports 方法测试")
    class SupportsTest {

        @Test
        @DisplayName("已注册的链应该返回 true")
        void supportsRegisteredChain() {
            assertThat(client.supports(ChainType.EVM)).isTrue();
        }

        @Test
        @DisplayName("未注册的链应该返回 false")
        void supportsUnregisteredChain() {
            assertThat(client.supports(ChainType.BTC)).isFalse();
        }
    }

    @Nested
    @DisplayName("adapter 方法测试")
    class AdapterTest {

        @Test
        @DisplayName("已注册的链应该返回适配器")
        void adapterReturnsRegistered() {
            ChainAdapter adapter = client.adapter(ChainType.EVM);

            assertThat(adapter).isSameAs(evmAdapter);
        }

        @Test
        @DisplayName("未注册的链应该抛出异常")
        void adapterThrowsForUnregistered() {
            assertThatThrownBy(() -> client.adapter(ChainType.BTC))
                    .isInstanceOf(UnsupportedChainException.class);
        }
    }

    @Nested
    @DisplayName("isValidAddress 方法测试")
    class IsValidAddressTest {

        @Test
        @DisplayName("应该委托给适配器")
        void delegatesToAdapter() {
            evmAdapter.setValidAddressResult(true);

            boolean result = client.isValidAddress(ChainType.EVM, "0x123");

            assertThat(result).isTrue();
            assertThat(evmAdapter.getLastValidatedAddress()).isEqualTo("0x123");
        }

        @Test
        @DisplayName("未注册的链应该抛出异常")
        void throwsForUnregisteredChain() {
            assertThatThrownBy(() -> client.isValidAddress(ChainType.BTC, "address"))
                    .isInstanceOf(UnsupportedChainException.class);
        }
    }

    @Nested
    @DisplayName("parseAddress 方法测试")
    class ParseAddressTest {

        @Test
        @DisplayName("应该委托给适配器")
        void delegatesToAdapter() {
            TestAddress expectedAddress = new TestAddress("0x123");
            evmAdapter.setParseAddressResult(expectedAddress);

            Address result = client.parseAddress(ChainType.EVM, "0x123");

            assertThat(result).isSameAs(expectedAddress);
        }
    }

    @Nested
    @DisplayName("deriveAddress 方法测试")
    class DeriveAddressTest {

        @Test
        @DisplayName("应该委托给适配器")
        void delegatesToAdapter() {
            TestAddress expectedAddress = new TestAddress("derived");
            evmAdapter.setDeriveAddressResult(expectedAddress);
            byte[] publicKey = new byte[65];

            Address result = client.deriveAddress(ChainType.EVM, publicKey);

            assertThat(result).isSameAs(expectedAddress);
        }
    }

    @Nested
    @DisplayName("encodeTransaction 方法测试")
    class EncodeTransactionTest {

        @Test
        @DisplayName("应该委托给适配器")
        void delegatesToAdapter() {
            byte[] expected = new byte[]{1, 2, 3};
            evmAdapter.setEncodeTransactionResult(expected);

            byte[] result = client.encodeTransaction(ChainType.EVM, null);

            assertThat(result).isSameAs(expected);
        }
    }

    @Nested
    @DisplayName("hashTransaction 方法测试")
    class HashTransactionTest {

        @Test
        @DisplayName("应该委托给适配器")
        void delegatesToAdapter() {
            byte[] expected = new byte[32];
            evmAdapter.setHashTransactionResult(expected);

            byte[] result = client.hashTransaction(ChainType.EVM, null);

            assertThat(result).isSameAs(expected);
        }
    }

    @Nested
    @DisplayName("hashMessage 方法测试")
    class HashMessageTest {

        @Test
        @DisplayName("应该委托给适配器")
        void delegatesToAdapter() {
            byte[] expected = new byte[32];
            evmAdapter.setHashMessageResult(expected);

            byte[] result = client.hashMessage(ChainType.EVM, "hello".getBytes());

            assertThat(result).isSameAs(expected);
        }
    }

    /**
     * 测试用的 ChainAdapter 实现
     */
    private static class TestChainAdapter implements ChainAdapter {

        private final ChainType chainType;
        private boolean validAddressResult = false;
        private String lastValidatedAddress;
        private Address parseAddressResult;
        private Address deriveAddressResult;
        private byte[] encodeTransactionResult = new byte[0];
        private byte[] hashTransactionResult = new byte[0];
        private byte[] hashMessageResult = new byte[0];

        TestChainAdapter(ChainType chainType) {
            this.chainType = chainType;
        }

        void setValidAddressResult(boolean result) {
            this.validAddressResult = result;
        }

        String getLastValidatedAddress() {
            return lastValidatedAddress;
        }

        void setParseAddressResult(Address result) {
            this.parseAddressResult = result;
        }

        void setDeriveAddressResult(Address result) {
            this.deriveAddressResult = result;
        }

        void setEncodeTransactionResult(byte[] result) {
            this.encodeTransactionResult = result;
        }

        void setHashTransactionResult(byte[] result) {
            this.hashTransactionResult = result;
        }

        void setHashMessageResult(byte[] result) {
            this.hashMessageResult = result;
        }

        @Override
        public ChainType getChainType() {
            return chainType;
        }

        @Override
        public boolean isValidAddress(String address) {
            this.lastValidatedAddress = address;
            return validAddressResult;
        }

        @Override
        public Address parseAddress(String address) {
            return parseAddressResult;
        }

        @Override
        public Address deriveAddress(byte[] publicKey) {
            return deriveAddressResult;
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
            return encodeTransactionResult;
        }

        @Override
        public byte[] hashTransaction(RawTransaction transaction) {
            return hashTransactionResult;
        }

        @Override
        public byte[] encodeSignedTransaction(SignedTransaction transaction) {
            return new byte[0];
        }

        @Override
        public byte[] hashMessage(byte[] message) {
            return hashMessageResult;
        }

        @Override
        public Address recoverSigner(byte[] hash, Signature signature) {
            return null;
        }
    }

    /**
     * 测试用的 Address 实现
     */
    private static class TestAddress implements Address {

        private final String value;

        TestAddress(String value) {
            this.value = value;
        }

        @Override
        public String toBase58() {
            return value;
        }

        @Override
        public byte[] toBytes() {
            return value.getBytes();
        }

        @Override
        public boolean isValid() {
            return true;
        }
    }
}