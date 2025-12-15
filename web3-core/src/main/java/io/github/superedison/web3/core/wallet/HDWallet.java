package io.github.superedison.web3.core.wallet;

import java.util.List;

/**
 * HD 钱包接口 (BIP-32/39/44)
 */
public interface HDWallet extends Wallet {

    /**
     * 获取助记词
     */
    List<String> getMnemonic();

    /**
     * 获取派生路径
     */
    String getDerivationPath();

    /**
     * 派生子钱包
     */
    HDWallet deriveChild(int index);

    /**
     * 按路径派生
     */
    HDWallet derivePath(String path);

    /**
     * 批量派生地址
     */
    List<Address> deriveAddresses(int startIndex, int count);
}