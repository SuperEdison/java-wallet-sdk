package io.github.superedison.web3.core.signer;

/**
 * 签名密钥接口（安全抽象）
 *
 * 设计原则：
 * - 私钥是"能力"，不是"数据"
 * - 私钥只能用来签名，不能被读取
 * - 私钥不能被 toString() / JSON 序列化 / 日志打印
 *
 * 安全注意事项：
 * - 使用完毕后必须调用 close() 或 destroy() 擦除私钥
 * - 推荐使用 try-with-resources 语法
 *
 * 示例：
 * <pre>{@code
 * try (SigningKey key = deriveSigningKey(...)) {
 *     Signature sig = key.sign(messageHash);
 * } // 自动擦除私钥
 * }</pre>
 */
public interface SigningKey extends AutoCloseable {

    /**
     * 对消息哈希签名
     *
     * @param hash 32字节消息哈希
     * @return 签名结果
     */
    Signature sign(byte[] hash);

    /**
     * 获取公钥（非压缩格式）
     *
     * @return 公钥字节数组
     */
    byte[] getPublicKey();

    /**
     * 获取签名算法类型
     */
    SignatureScheme getScheme();

    /**
     * 安全销毁私钥
     * 调用后私钥将被清零，SigningKey 不可再使用
     */
    void destroy();

    /**
     * 是否已销毁
     */
    boolean isDestroyed();

    /**
     * 实现 AutoCloseable，调用 destroy()
     */
    @Override
    default void close() {
        destroy();
    }
}
