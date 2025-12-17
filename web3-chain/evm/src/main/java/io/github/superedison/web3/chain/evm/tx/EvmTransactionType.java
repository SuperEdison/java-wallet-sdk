package io.github.superedison.web3.chain.evm.tx;

/**
 * EVM 交易类型
 */
public enum EvmTransactionType {
    /**
     * Legacy 交易 (EIP-155)
     */
    LEGACY,

    /**
     * EIP-2930 交易 (Access List)
     */
    EIP2930,

    /**
     * EIP-1559 交易 (动态手续费)
     */
    EIP1559
}
