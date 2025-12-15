package io.github.superedison.web3.core.transaction;

/**
 * 交易类型枚举
 */
public enum TransactionType {

    /**
     * EVM Legacy
     */
    EVM_LEGACY,

    /**
     * EVM EIP-1559
     */
    EVM_EIP1559,

    /**
     * EVM EIP-2930
     */
    EVM_EIP2930,

    /**
     * Bitcoin P2PKH
     */
    BTC_P2PKH,

    /**
     * Bitcoin P2WPKH (SegWit)
     */
    BTC_P2WPKH,

    /**
     * Bitcoin P2TR (Taproot)
     */
    BTC_P2TR,

    /**
     * Solana
     */
    SOLANA,

    /**
     * Aptos
     */
    APTOS,

    /**
     * TRON Transfer (TRX)
     */
    TRON_TRANSFER,

    /**
     * TRON TRC-20 Token Transfer
     */
    TRON_TRC20
}