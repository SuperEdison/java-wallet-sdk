package io.github.superedison.web3.crypto.eip712;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * EIP-712 / TIP-712 域分隔符（EIP712Domain）字段容器。
 *
 * <p>域类型名固定为 {@code "EIP712Domain"}。类型由“实际提供的字段”按 EIP-712 规范的固定顺序
 * name, version, chainId, verifyingContract, salt 动态构造，未设置的字段不参与编码。
 *
 * <p>{@code verifyingContract} 的地址编码由链注入的 {@link AddressCodec} 处理（EVM 0x-hex / TRON 剥 0x41）。
 * chainId 为链自身的值：EVM 用 EIP-155 chainId；TRON 用 {@code block.chainid & 0xffffffff}（由调用方传入）。
 */
public final class Eip712Domain {

    /** EIP-712 域类型名。 */
    static final String DOMAIN_TYPE_NAME = "EIP712Domain";

    private final String name;
    private final String version;
    private final BigInteger chainId;
    private final Object verifyingContract;
    private final byte[] salt;

    private Eip712Domain(Builder b) {
        this.name = b.name;
        this.version = b.version;
        this.chainId = b.chainId;
        this.verifyingContract = copyByteArray(b.verifyingContract);
        this.salt = b.salt == null ? null : b.salt.clone();
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * 按 EIP-712 规范顺序返回“实际提供”的域字段，未设置的字段被跳过。
     */
    List<Eip712TypedData.Field> presentFields() {
        List<Eip712TypedData.Field> fields = new ArrayList<>(5);
        if (name != null) fields.add(new Eip712TypedData.Field("name", "string"));
        if (version != null) fields.add(new Eip712TypedData.Field("version", "string"));
        if (chainId != null) fields.add(new Eip712TypedData.Field("chainId", "uint256"));
        if (verifyingContract != null) fields.add(new Eip712TypedData.Field("verifyingContract", "address"));
        if (salt != null) fields.add(new Eip712TypedData.Field("salt", "bytes32"));
        return List.copyOf(fields);
    }

    /** 与 {@link #presentFields()} 对应的取值映射。 */
    Map<String, Object> valueMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        if (name != null) m.put("name", name);
        if (version != null) m.put("version", version);
        if (chainId != null) m.put("chainId", chainId);
        if (verifyingContract != null) m.put("verifyingContract", copyByteArray(verifyingContract));
        if (salt != null) m.put("salt", salt.clone());
        return Collections.unmodifiableMap(m);
    }

    private static Object copyByteArray(Object value) {
        return value instanceof byte[] bytes ? bytes.clone() : value;
    }

    public static final class Builder {
        private String name;
        private String version;
        private BigInteger chainId;
        private Object verifyingContract;
        private byte[] salt;

        public Builder name(String name) { this.name = name; return this; }

        public Builder version(String version) { this.version = version; return this; }

        public Builder chainId(long chainId) { this.chainId = BigInteger.valueOf(chainId); return this; }

        public Builder chainId(BigInteger chainId) { this.chainId = chainId; return this; }

        /** verifyingContract：地址值，接受形式由链的 {@link AddressCodec} 决定（EVM 0x-hex、TRON base58/hex/对象）。 */
        public Builder verifyingContract(Object verifyingContract) {
            this.verifyingContract = copyByteArray(verifyingContract);
            return this;
        }

        public Builder salt(byte[] salt) {
            if (salt != null && salt.length != 32) {
                throw new IllegalArgumentException("salt must be 32 bytes");
            }
            this.salt = salt == null ? null : salt.clone();
            return this;
        }

        public Eip712Domain build() {
            if (name == null && version == null && chainId == null
                    && verifyingContract == null && salt == null) {
                throw new IllegalArgumentException("EIP712Domain must have at least one field");
            }
            return new Eip712Domain(this);
        }
    }
}
