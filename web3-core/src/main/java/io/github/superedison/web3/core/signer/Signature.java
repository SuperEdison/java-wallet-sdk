package io.github.superedison.web3.core.signer;

/**
 * 签名结果接口
 * 通用签名抽象，不绑定任何链
 */
public interface Signature {

    /**
     * 获取签名字节
     */
    byte[] bytes();

    /**
     * 获取签名算法
     */
    SignatureScheme scheme();

    /**
     * 获取签名长度
     */
    default int length() {
        return bytes().length;
    }
}