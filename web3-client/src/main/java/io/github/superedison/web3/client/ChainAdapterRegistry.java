package io.github.superedison.web3.client;

import io.github.superedison.web3.chain.ChainAdapter;
import io.github.superedison.web3.chain.ChainType;
import io.github.superedison.web3.chain.exception.UnsupportedChainException;

import java.util.Map;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 链适配器注册表
 * 管理 ChainType → ChainAdapter 的映射
 */
public final class ChainAdapterRegistry {

    private final Map<ChainType, ChainAdapter> adapters = new ConcurrentHashMap<>();

    /**
     * 注册适配器
     */
    public ChainAdapterRegistry register(ChainAdapter adapter) {
        adapters.put(adapter.getChainType(), adapter);
        return this;
    }

    /**
     * 获取适配器
     * @throws UnsupportedChainException 如果链类型未注册
     */
    public ChainAdapter get(ChainType chainType) {
        ChainAdapter adapter = adapters.get(chainType);
        if (adapter == null) {
            throw new UnsupportedChainException(chainType);
        }
        return adapter;
    }

    /**
     * 获取适配器（可选）
     */
    public Optional<ChainAdapter> find(ChainType chainType) {
        return Optional.ofNullable(adapters.get(chainType));
    }

    /**
     * 检查是否支持指定链
     */
    public boolean supports(ChainType chainType) {
        return adapters.containsKey(chainType);
    }

    /**
     * 从 ServiceLoader 自动发现并注册适配器
     */
    public ChainAdapterRegistry autoDiscover() {
        ServiceLoader<ChainAdapter> loader = ServiceLoader.load(ChainAdapter.class);
        for (ChainAdapter adapter : loader) {
            register(adapter);
        }
        return this;
    }

    /**
     * 创建空注册表
     */
    public static ChainAdapterRegistry create() {
        return new ChainAdapterRegistry();
    }

    /**
     * 创建并自动发现适配器
     */
    public static ChainAdapterRegistry withAutoDiscover() {
        return new ChainAdapterRegistry().autoDiscover();
    }
}