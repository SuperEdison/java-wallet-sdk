package io.github.superedison.web3.chain.tron.tx;

/**
 * TRON 交易类型
 */
public enum TronTransactionType {

    /**
     * TRX 转账
     */
    TRANSFER_CONTRACT(1),

    /**
     * 智能合约调用 (TRC-20)
     */
    TRIGGER_SMART_CONTRACT(31);

    private final int value;

    TronTransactionType(int value) {
        this.value = value;
    }

    /**
     * 获取合约类型值
     * @return 合约类型数值
     */
    public int getValue() {
        return value;
    }

    /**
     * 根据值获取类型
     * @param value 合约类型值
     * @return TronTransactionType
     */
    public static TronTransactionType fromValue(int value) {
        for (TronTransactionType type : values()) {
            if (type.value == value) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown TRON transaction type: " + value);
    }
}
