package io.github.superedison.web3.chain.exception;

/**
 * 签名异常
 */
public class SigningException extends ChainException {

    public SigningException(String message) {
        super(message);
    }

    public SigningException(String message, Throwable cause) {
        super(message, cause);
    }
}