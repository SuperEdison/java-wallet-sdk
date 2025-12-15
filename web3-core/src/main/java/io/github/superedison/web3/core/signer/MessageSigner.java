package io.github.superedison.web3.core.signer;

/**
 * 消息签名器接口
 */
public interface MessageSigner {

    /**
     * 对消息签名
     */
    Signature signMessage(byte[] message);

    /**
     * 验证消息签名
     */
    boolean verifyMessage(byte[] message, Signature signature);
}