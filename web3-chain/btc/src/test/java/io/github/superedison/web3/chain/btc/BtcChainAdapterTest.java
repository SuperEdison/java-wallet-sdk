package io.github.superedison.web3.chain.btc;

import io.github.superedison.web3.chain.btc.address.BtcNetwork;
import io.github.superedison.web3.chain.btc.tx.BtcRawTransaction;
import io.github.superedison.web3.chain.spi.ChainType;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

/**
 * Bitcoin ChainAdapter 测试
 */
class BtcChainAdapterTest {

    @Test
    void testChainType() {
        BtcChainAdapter adapter = new BtcChainAdapter();
        assertThat(adapter.chainType()).isEqualTo(ChainType.BTC);
    }

    @Test
    void testDefaultNetwork() {
        BtcChainAdapter adapter = new BtcChainAdapter();
        assertThat(adapter.getNetwork()).isEqualTo(BtcNetwork.MAINNET);
    }

    @Test
    void testCustomNetwork() {
        BtcChainAdapter adapter = new BtcChainAdapter(BtcNetwork.TESTNET);
        assertThat(adapter.getNetwork()).isEqualTo(BtcNetwork.TESTNET);
    }

    @Test
    void testTransactionBuilder() {
        byte[] prevTxHash = new byte[32];
        for (int i = 0; i < 32; i++) {
            prevTxHash[i] = (byte) i;
        }

        byte[] scriptPubKey = new byte[]{0x76, (byte) 0xa9, 0x14};

        BtcRawTransaction tx = BtcRawTransaction.builder()
                .version(2)
                .addInput(prevTxHash, 0)
                .addOutput(100000L, scriptPubKey)
                .lockTime(0)
                .build();

        assertThat(tx.getVersion()).isEqualTo(2);
        assertThat(tx.getInputs()).hasSize(1);
        assertThat(tx.getOutputs()).hasSize(1);
        assertThat(tx.getLockTime()).isEqualTo(0);
        assertThat(tx.isSegwit()).isFalse();
    }

    @Test
    void testTransactionBuilderWithMultipleInputsOutputs() {
        byte[] prevTxHash1 = new byte[32];
        byte[] prevTxHash2 = new byte[32];
        byte[] scriptPubKey = new byte[25];

        BtcRawTransaction tx = BtcRawTransaction.builder()
                .addInput(prevTxHash1, 0)
                .addInput(prevTxHash2, 1)
                .addOutput(50000L, scriptPubKey)
                .addOutput(49000L, scriptPubKey)
                .build();

        assertThat(tx.getInputs()).hasSize(2);
        assertThat(tx.getOutputs()).hasSize(2);
    }

    @Test
    void testSegwitFlag() {
        byte[] prevTxHash = new byte[32];
        byte[] scriptPubKey = new byte[25];
        byte[][] witness = new byte[][]{{0x01}, {0x02}};

        BtcRawTransaction tx = BtcRawTransaction.builder()
                .addInput(prevTxHash, 0, new byte[0], 0xffffffffL, witness)
                .addOutput(100000L, scriptPubKey)
                .build();

        assertThat(tx.isSegwit()).isTrue();
    }

    @Test
    void testTransactionBuilderValidation() {
        byte[] prevTxHash = new byte[32];

        // 没有输出应该失败
        assertThatThrownBy(() ->
                BtcRawTransaction.builder()
                        .addInput(prevTxHash, 0)
                        .build()
        ).isInstanceOf(IllegalStateException.class);

        // 没有输入应该失败
        byte[] scriptPubKey = new byte[25];
        assertThatThrownBy(() ->
                BtcRawTransaction.builder()
                        .addOutput(100000L, scriptPubKey)
                        .build()
        ).isInstanceOf(IllegalStateException.class);
    }
}
