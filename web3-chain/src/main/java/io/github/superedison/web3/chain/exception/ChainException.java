package io.github.superedison.web3.chain.exception;

/**
 * 链异常基类
 */
public class ChainException extends RuntimeException {

    public ChainException(String message) {
        super(message);
    }

    public ChainException(String message, Throwable cause) {
        super(message, cause);
    }
}