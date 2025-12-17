package io.github.superedison.web3.client;

import io.github.superedison.web3.chain.spi.ChainAdapter;
import io.github.superedison.web3.chain.spi.ChainType;
import io.github.superedison.web3.core.tx.RawTransaction;
import io.github.superedison.web3.core.tx.SignedTransaction;

/**
 * Web3 客户端：统一入口，委托给对应的 ChainAdapter。
 */
public final class Web3Client {

    private final ChainAdapterRegistry registry;

    private Web3Client(ChainAdapterRegistry registry) {
        this.registry = registry;
    }

    // ========== 适配器访问 ==========

    /**
     * 获取指定链的适配器。
     */
    public ChainAdapter<?, ?> adapter(ChainType chainType) {
        return registry.get(chainType);
    }

    /**
     * 获取类型化的适配器（调用方需保证类型匹配）。
     */
    @SuppressWarnings("unchecked")
    public <TX extends RawTransaction, STX extends SignedTransaction<TX>> ChainAdapter<TX, STX> typedAdapter(ChainType chainType) {
        return registry.getTyped(chainType);
    }

    /**
     * 检查是否支持指定链。
     */
    public boolean supports(ChainType chainType) {
        return registry.supports(chainType);
    }

    // ========== Builder ==========

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private ChainAdapterRegistry registry;

        /**
         * 使用指定的注册表。
         */
        public Builder registry(ChainAdapterRegistry registry) {
            this.registry = registry;
            return this;
        }


        /**
         * 注册适配器。
         */
        public Builder register(ChainAdapter<?, ?> adapter) {
            if (this.registry == null) {
                this.registry = ChainAdapterRegistry.create();
            }
            this.registry.register(adapter);
            return this;
        }

        /**
         * 自动发现并注册适配器。
         */
        public Builder autoDiscover() {
            if (this.registry == null) {
                this.registry = ChainAdapterRegistry.create();
            }
            this.registry.autoDiscover();
            return this;
        }

        public Web3Client build() {
            if (this.registry == null) {
                this.registry = ChainAdapterRegistry.create();
            }
            return new Web3Client(registry);
        }
    }
}
