package io.github.superedison.web3.client.derive;

import io.github.superedison.web3.chain.spi.ChainType;
import io.github.superedison.web3.core.signer.SigningKey;

/**
 * 链派生结果
 *
 * 包含派生的地址和签名密钥，实现 AutoCloseable 以支持自动销毁。
 *
 * 使用示例：
 * <pre>{@code
 * try (ChainDeriveResult result = deriver.deriveForUser("user123", ChainType.EVM)) {
 *     String address = result.address();
 *     Signature sig = result.signingKey().sign(txHash);
 * } // 自动销毁 SigningKey
 * }</pre>
 *
 * @param userId       用户 ID（如果通过路径派生则为 null）
 * @param accountIndex 账户索引
 * @param path         派生路径
 * @param chainType    链类型
 * @param address      格式化的地址字符串
 * @param signingKey   签名密钥（调用者负责销毁）
 */
public record ChainDeriveResult(
        String userId,
        int accountIndex,
        String path,
        ChainType chainType,
        String address,
        SigningKey signingKey
) implements AutoCloseable {

    /**
     * 销毁签名密钥
     */
    @Override
    public void close() {
        if (signingKey != null) {
            signingKey.destroy();
        }
    }

    /**
     * 是否已销毁
     */
    public boolean isDestroyed() {
        return signingKey == null || signingKey.isDestroyed();
    }

    @Override
    public String toString() {
        return "ChainDeriveResult{" +
                "userId='" + userId + '\'' +
                ", accountIndex=" + accountIndex +
                ", path='" + path + '\'' +
                ", chainType=" + chainType +
                ", address='" + address + '\'' +
                ", signingKey=***REDACTED***" +
                '}';
    }
}
