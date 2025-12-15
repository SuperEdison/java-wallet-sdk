package io.github.superedison.web3.core.exception;

/**
 * 签名相关异常
 */
public class SigningException extends Web3Exception {

    public SigningException(String message) {
        super(message);
    }

    public SigningException(String message, Throwable cause) {
        super(message, cause);
    }

    public SigningException(ErrorCode errorCode, String message) {
        super(errorCode, message);
    }

    public SigningException(ErrorCode errorCode, String message, Throwable cause) {
        super(errorCode, message, cause);
    }
}