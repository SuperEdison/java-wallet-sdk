package io.github.superedison.web3.core.signer;

import io.github.superedison.web3.core.transaction.RawTransaction;
import io.github.superedison.web3.core.transaction.SignedTransaction;

/**
 * 交易签名器接口
 */
public interface TransactionSigner {

    /**
     * 对交易签名
     */
    SignedTransaction signTransaction(RawTransaction transaction);

    /**
     * 验证交易签名
     */
    boolean verifyTransaction(SignedTransaction transaction);
}