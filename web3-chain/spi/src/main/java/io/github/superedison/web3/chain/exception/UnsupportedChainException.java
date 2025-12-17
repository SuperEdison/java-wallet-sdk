package io.github.superedison.web3.chain.exception;

import io.github.superedison.web3.chain.spi.ChainType;

/**
 * 不支持的链类型。
 */
public class UnsupportedChainException extends ChainException {

    private final ChainType chainType;

    public UnsupportedChainException(ChainType chainType) {
        super("Unsupported chain: " + chainType);
        this.chainType = chainType;
    }

    public ChainType getChainType() {
        return chainType;
    }
}
