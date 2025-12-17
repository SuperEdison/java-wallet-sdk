package io.github.superedison.web3.chain.spi;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * AddressEncoder 注册表
 *
 * 使用 ServiceLoader 自动发现和注册 AddressEncoder 实现。
 *
 * 使用示例：
 * <pre>{@code
 * AddressEncoder encoder = AddressEncoderRegistry.get(ChainType.EVM);
 * String address = encoder.encode(publicKey);
 * }</pre>
 */
public final class AddressEncoderRegistry {

    private static final Map<ChainType, AddressEncoder> ENCODERS = new ConcurrentHashMap<>();
    private static volatile boolean initialized = false;

    private AddressEncoderRegistry() {}

    /**
     * 获取指定链的地址编码器
     *
     * @param chainType 链类型
     * @return AddressEncoder 实例
     * @throws IllegalArgumentException 如果没有找到对应的编码器
     */
    public static AddressEncoder get(ChainType chainType) {
        ensureInitialized();
        AddressEncoder encoder = ENCODERS.get(chainType);
        if (encoder == null) {
            throw new IllegalArgumentException("No AddressEncoder found for chain: " + chainType);
        }
        return encoder;
    }

    /**
     * 获取指定链的地址编码器（可选）
     *
     * @param chainType 链类型
     * @return Optional<AddressEncoder>
     */
    public static Optional<AddressEncoder> getOptional(ChainType chainType) {
        ensureInitialized();
        return Optional.ofNullable(ENCODERS.get(chainType));
    }

    /**
     * 检查是否支持指定链
     *
     * @param chainType 链类型
     * @return 是否支持
     */
    public static boolean isSupported(ChainType chainType) {
        ensureInitialized();
        return ENCODERS.containsKey(chainType);
    }

    /**
     * 获取所有支持的链类型
     *
     * @return 不可变的链类型集合
     */
    public static Set<ChainType> supportedChains() {
        ensureInitialized();
        return Collections.unmodifiableSet(ENCODERS.keySet());
    }

    /**
     * 手动注册 AddressEncoder
     *
     * 主要用于测试或动态注册
     *
     * @param encoder AddressEncoder 实例
     */
    public static void register(AddressEncoder encoder) {
        ENCODERS.put(encoder.chainType(), encoder);
    }

    /**
     * 重新加载所有编码器
     *
     * 清除缓存并重新从 ServiceLoader 加载
     */
    public static synchronized void reload() {
        ENCODERS.clear();
        initialized = false;
        ensureInitialized();
    }

    private static void ensureInitialized() {
        if (!initialized) {
            synchronized (AddressEncoderRegistry.class) {
                if (!initialized) {
                    loadFromServiceLoader();
                    initialized = true;
                }
            }
        }
    }

    private static void loadFromServiceLoader() {
        ServiceLoader<AddressEncoder> loader = ServiceLoader.load(AddressEncoder.class);
        for (AddressEncoder encoder : loader) {
            ENCODERS.put(encoder.chainType(), encoder);
        }
    }
}
