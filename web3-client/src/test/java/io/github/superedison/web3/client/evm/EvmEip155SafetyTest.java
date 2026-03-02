package io.github.superedison.web3.client.evm;

import io.github.superedison.web3.chain.evm.tx.EvmRawTransaction;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("EVM EIP-155 安全边界测试")
class EvmEip155SafetyTest {

    @Test
    @DisplayName("chainId 为 0 时应拒绝构建")
    void shouldRejectZeroChainId() {
        assertThatThrownBy(() -> EvmRawTransaction.builder().chainId(0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("chainId must be positive");
    }

    @Test
    @DisplayName("chainId 为负数时应拒绝构建")
    void shouldRejectNegativeChainId() {
        assertThatThrownBy(() -> EvmRawTransaction.builder().chainId(-1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("chainId must be positive");
    }
}
