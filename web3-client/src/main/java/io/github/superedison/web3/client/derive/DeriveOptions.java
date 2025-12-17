package io.github.superedison.web3.client.derive;

import io.github.superedison.web3.chain.btc.address.BtcAddressType;
import io.github.superedison.web3.chain.btc.address.BtcNetwork;

/**
 * 账户派生选项
 *
 * 用于自定义派生行为，特别是 BTC 的多地址类型支持。
 *
 * 使用示例：
 * <pre>{@code
 * DeriveOptions opts = DeriveOptions.builder()
 *     .btcAddressType(BtcAddressType.P2TR)
 *     .btcNetwork(BtcNetwork.MAINNET)
 *     .build();
 *
 * ChainDeriveResult result = deriver.deriveForUser("user123", ChainType.BTC, opts);
 * }</pre>
 */
public final class DeriveOptions {

    private final BtcAddressType btcAddressType;
    private final BtcNetwork btcNetwork;
    private final int change;
    private final int addressIndex;

    private DeriveOptions(Builder builder) {
        this.btcAddressType = builder.btcAddressType;
        this.btcNetwork = builder.btcNetwork;
        this.change = builder.change;
        this.addressIndex = builder.addressIndex;
    }

    /**
     * 默认选项
     */
    public static DeriveOptions defaults() {
        return builder().build();
    }

    /**
     * 创建构建器
     */
    public static Builder builder() {
        return new Builder();
    }

    // ==================== Getters ====================

    /**
     * 获取 BTC 地址类型
     *
     * @return BTC 地址类型，默认 P2WPKH
     */
    public BtcAddressType getBtcAddressType() {
        return btcAddressType;
    }

    /**
     * 获取 BTC 网络
     *
     * @return BTC 网络，默认 MAINNET
     */
    public BtcNetwork getBtcNetwork() {
        return btcNetwork;
    }

    /**
     * 获取 change 索引
     *
     * @return change 索引（0=外部地址, 1=找零地址）
     */
    public int getChange() {
        return change;
    }

    /**
     * 获取 address_index
     *
     * @return 地址索引
     */
    public int getAddressIndex() {
        return addressIndex;
    }

    @Override
    public String toString() {
        return "DeriveOptions{" +
                "btcAddressType=" + btcAddressType +
                ", btcNetwork=" + btcNetwork +
                ", change=" + change +
                ", addressIndex=" + addressIndex +
                '}';
    }

    /**
     * DeriveOptions 构建器
     */
    public static final class Builder {
        private BtcAddressType btcAddressType = BtcAddressType.P2WPKH;
        private BtcNetwork btcNetwork = BtcNetwork.MAINNET;
        private int change = 0;
        private int addressIndex = 0;

        private Builder() {}

        /**
         * 设置 BTC 地址类型
         *
         * @param type 地址类型 (P2PKH, P2SH_P2WPKH, P2WPKH, P2TR)
         */
        public Builder btcAddressType(BtcAddressType type) {
            this.btcAddressType = type;
            return this;
        }

        /**
         * 设置 BTC 网络
         *
         * @param network 网络 (MAINNET, TESTNET, REGTEST)
         */
        public Builder btcNetwork(BtcNetwork network) {
            this.btcNetwork = network;
            return this;
        }

        /**
         * 设置 change 索引
         *
         * @param change 0=外部地址, 1=找零地址
         */
        public Builder change(int change) {
            if (change < 0 || change > 1) {
                throw new IllegalArgumentException("Change must be 0 or 1");
            }
            this.change = change;
            return this;
        }

        /**
         * 设置 address_index
         *
         * @param index 地址索引 (>= 0)
         */
        public Builder addressIndex(int index) {
            if (index < 0) {
                throw new IllegalArgumentException("Address index must be non-negative");
            }
            this.addressIndex = index;
            return this;
        }

        /**
         * 构建 DeriveOptions
         */
        public DeriveOptions build() {
            return new DeriveOptions(this);
        }
    }
}
