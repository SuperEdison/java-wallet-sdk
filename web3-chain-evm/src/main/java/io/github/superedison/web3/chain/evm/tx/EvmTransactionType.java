package io.github.superedison.web3.chain.evm.tx;

/**
 * EVM 交易类型
 */
public enum EvmTransactionType {

    /**
     * Legacy 交易 (pre EIP-2718)
     */
    LEGACY,

    /**
     * EIP-2930 访问列表交易
     */
    EIP2930,

    /**
     * EIP-1559 动态费用交易
     */
    EIP1559
}