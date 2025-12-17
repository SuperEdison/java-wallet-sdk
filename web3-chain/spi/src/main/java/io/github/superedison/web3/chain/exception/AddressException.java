package io.github.superedison.web3.chain.exception;

/**
 * 地址相关异常。
 */
public class AddressException extends ChainException {

    public AddressException(String message) {
        super(message);
    }

    public AddressException(String message, Throwable cause) {
        super(message, cause);
    }

    public static AddressException invalidFormat(String value) {
        return new AddressException("Invalid address format: " + value);
    }
}
