package io.github.superedison.web3.client;

import io.github.superedison.web3.chain.exception.UnsupportedChainException;
import io.github.superedison.web3.chain.spi.ChainAdapter;
import io.github.superedison.web3.chain.spi.ChainType;
import io.github.superedison.web3.core.signer.SigningKey;
import io.github.superedison.web3.core.tx.RawTransaction;
import io.github.superedison.web3.core.tx.SignedTransaction;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

@DisplayName("Web3Client 客户端测试")
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
    @DisplayName("adapter 与 supports")
    class AdapterAccessTest {

        @Test
        @DisplayName("已注册链应返回对应 adapter")
        void shouldReturnAdapter() {
            ChainAdapter<?, ?> adapter = client.adapter(ChainType.EVM);
            assertThat(adapter).isSameAs(evmAdapter);
        }

        @Test
        @DisplayName("未注册链应抛出 UnsupportedChainException")
        void shouldThrowWhenUnsupported() {
            assertThatThrownBy(() -> client.adapter(ChainType.BTC))
                    .isInstanceOf(UnsupportedChainException.class);
        }

        @Test
        @DisplayName("supports 返回正确状态")
        void shouldReportSupports() {
            assertThat(client.supports(ChainType.EVM)).isTrue();
            assertThat(client.supports(ChainType.BTC)).isFalse();
        }
    }

    /**
     * 测试用的 ChainAdapter 实现。
     */
    private static class TestChainAdapter implements ChainAdapter<DummyRawTx, DummySignedTx> {
        private final ChainType chainType;

        TestChainAdapter(ChainType chainType) {
            this.chainType = chainType;
        }

        @Override
        public ChainType chainType() {
            return chainType;
        }

        @Override
        public DummySignedTx sign(DummyRawTx tx, SigningKey key) {
            return new DummySignedTx(tx);
        }

        @Override
        public byte[] rawBytes(DummySignedTx signedTx) {
            return signedTx.rawBytes();
        }

        @Override
        public byte[] txHash(DummySignedTx signedTx) {
            return signedTx.txHash();
        }
    }

    private static class DummyRawTx implements RawTransaction {
        // marker
    }

    private static class DummySignedTx implements SignedTransaction<DummyRawTx> {
        private final DummyRawTx rawTx;

        DummySignedTx(DummyRawTx rawTx) {
            this.rawTx = rawTx;
        }

        @Override
        public DummyRawTx rawTransaction() {
            return rawTx;
        }

        @Override
        public byte[] rawBytes() {
            return new byte[0];
        }

        @Override
        public byte[] txHash() {
            return new byte[0];
        }

        @Override
        public String from() {
            return "0x0";
        }
    }
}
