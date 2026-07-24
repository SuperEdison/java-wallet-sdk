package io.github.superedison.web3.crypto.eip712;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 一份完整的 EIP-712 / TIP-712 结构化数据：类型定义 + 主类型 + 域 + 消息取值。
 *
 * <p>对应 ethers {@code signTypedData(domain, types, value)} 与 tronweb {@code signTypedData(domain, types, message)}
 * 的三个入参。{@code types} 里<b>不要</b>包含 {@code EIP712Domain}——域类型由 {@link Eip712Domain} 的实际字段自动构造。
 *
 * <p>取值约定（{@link #message()} 与嵌套 struct 均为 {@code Map<String,Object>}）：
 * <ul>
 *   <li>{@code uintN}/{@code intN}（必须带位宽，无 {@code uint}/{@code int} 别名）：BigInteger / Long / Integer / 十进制或 0x 十六进制 String</li>
 *   <li>{@code trcToken}（TRON 扩展，按 uint256 编码）：同上</li>
 *   <li>{@code address}：形式由链的 {@link AddressCodec} 决定</li>
 *   <li>{@code bool}：Boolean / 0|1；{@code string}：String；{@code bytes}/{@code bytesN}：byte[] 或十六进制 String</li>
 *   <li>struct：嵌套 {@code Map<String,Object>}；数组 {@code T[]}/{@code T[n]}：List 或数组</li>
 * </ul>
 */
public final class Eip712TypedData {

    private static final int MAX_VALUE_NESTING_DEPTH = 128;
    private static final Pattern IDENTIFIER = Pattern.compile("^[A-Za-z_$][A-Za-z0-9_$]*$");
    private static final Pattern INTEGER_TYPE = Pattern.compile("^(u?int)(\\d*)$");
    private static final Pattern BYTES_TYPE = Pattern.compile("^bytes(\\d*)$");

    /** 类型成员定义：{@code type name}（顺序即编码顺序）。 */
    public record Field(String name, String type) {}

    private final Map<String, List<Field>> types;
    private final String primaryType;
    private final Eip712Domain domain;
    private final Map<String, Object> message;

    private Eip712TypedData(Builder b) {
        this.types = snapshotTypes(b.types);
        this.primaryType = b.primaryType;
        this.domain = b.domain;
        this.message = snapshotMessage(b.message);
    }

    public Map<String, List<Field>> types() { return types; }

    public String primaryType() { return primaryType; }

    public Eip712Domain domain() { return domain; }

    /**
     * 返回消息的只读快照。Map/List 不能修改；其中的 byte[] 也与内部状态隔离。
     */
    public Map<String, Object> message() { return snapshotMessage(message); }

    private static Map<String, List<Field>> snapshotTypes(Map<String, List<Field>> source) {
        Map<String, List<Field>> copy = new LinkedHashMap<>(source.size());
        for (Map.Entry<String, List<Field>> entry : source.entrySet()) {
            copy.put(entry.getKey(), List.copyOf(entry.getValue()));
        }
        return Collections.unmodifiableMap(copy);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> snapshotMessage(Map<String, Object> source) {
        return (Map<String, Object>) snapshotValue(
                source, new IdentityHashMap<>(), new IdentityHashMap<>(), 0);
    }

    private static Object snapshotValue(
            Object value,
            IdentityHashMap<Object, Boolean> ancestors,
            IdentityHashMap<Object, Object> snapshots,
            int depth) {
        if (value instanceof byte[] bytes) {
            return bytes.clone();
        }
        if (value instanceof Map<?, ?> map) {
            Object existing = snapshots.get(value);
            if (existing != null) return existing;
            enterContainer(value, ancestors, depth);
            try {
                Map<Object, Object> copy = new LinkedHashMap<>();
                for (Map.Entry<?, ?> entry : map.entrySet()) {
                    copy.put(entry.getKey(), snapshotValue(
                            entry.getValue(), ancestors, snapshots, depth + 1));
                }
                Map<Object, Object> snapshot = Collections.unmodifiableMap(copy);
                snapshots.put(value, snapshot);
                return snapshot;
            } finally {
                ancestors.remove(value);
            }
        }
        if (value instanceof List<?> list) {
            Object existing = snapshots.get(value);
            if (existing != null) return existing;
            enterContainer(value, ancestors, depth);
            try {
                List<Object> copy = new ArrayList<>();
                for (Object element : list) {
                    copy.add(snapshotValue(element, ancestors, snapshots, depth + 1));
                }
                List<Object> snapshot = Collections.unmodifiableList(copy);
                snapshots.put(value, snapshot);
                return snapshot;
            } finally {
                ancestors.remove(value);
            }
        }
        if (value instanceof Object[] array) {
            Object existing = snapshots.get(value);
            if (existing != null) return existing;
            enterContainer(value, ancestors, depth);
            try {
                List<Object> copy = new ArrayList<>();
                for (Object element : array) {
                    copy.add(snapshotValue(element, ancestors, snapshots, depth + 1));
                }
                List<Object> snapshot = Collections.unmodifiableList(copy);
                snapshots.put(value, snapshot);
                return snapshot;
            } finally {
                ancestors.remove(value);
            }
        }
        return value;
    }

    private static void enterContainer(
            Object value, IdentityHashMap<Object, Boolean> ancestors, int depth) {
        if (depth >= MAX_VALUE_NESTING_DEPTH) {
            throw new IllegalArgumentException(
                    "EIP-712 message nesting exceeds " + MAX_VALUE_NESTING_DEPTH + " containers");
        }
        if (ancestors.put(value, Boolean.TRUE) != null) {
            throw new IllegalArgumentException("Cyclic EIP-712 message values are not supported");
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private final Map<String, List<Field>> types = new LinkedHashMap<>();
        private String primaryType;
        private Eip712Domain domain;
        private Map<String, Object> message;

        /** 定义一个 struct 类型；成员顺序即编码顺序。 */
        public Builder addType(String name, Field... fields) {
            if (Eip712Domain.DOMAIN_TYPE_NAME.equals(name)) {
                throw new IllegalArgumentException(
                        "Do not declare EIP712Domain in types; it is built from the Eip712Domain fields");
            }
            this.types.put(name, List.of(fields));
            return this;
        }

        public Builder primaryType(String primaryType) {
            this.primaryType = primaryType;
            return this;
        }

        public Builder domain(Eip712Domain domain) {
            this.domain = domain;
            return this;
        }

        public Builder message(Map<String, Object> message) {
            this.message = new LinkedHashMap<>(message);
            return this;
        }

        public Eip712TypedData build() {
            if (domain == null) throw new IllegalArgumentException("domain is required");
            if (primaryType == null || primaryType.isEmpty()) {
                throw new IllegalArgumentException("primaryType is required");
            }
            if (!types.containsKey(primaryType)) {
                throw new IllegalArgumentException("primaryType '" + primaryType + "' is not declared in types");
            }
            if (message == null) throw new IllegalArgumentException("message is required");
            validateSchema(types);
            return new Eip712TypedData(this);
        }

        private static void validateSchema(Map<String, List<Field>> types) {
            for (Map.Entry<String, List<Field>> entry : types.entrySet()) {
                String typeName = entry.getKey();
                requireIdentifier("struct type", typeName);
                if (isAtomicTypeName(typeName)) {
                    throw new IllegalArgumentException(
                            "Struct type name conflicts with an atomic type: " + typeName);
                }

                Set<String> fieldNames = new HashSet<>();
                for (Field field : entry.getValue()) {
                    if (field == null) {
                        throw new IllegalArgumentException("Null field in struct type " + typeName);
                    }
                    requireIdentifier("field", field.name());
                    if (!fieldNames.add(field.name())) {
                        throw new IllegalArgumentException(
                                "Duplicate field '" + field.name() + "' in struct type " + typeName);
                    }
                    validateFieldType(field.type(), types);
                }
            }
        }

        private static void validateFieldType(String fieldType, Map<String, List<Field>> types) {
            if (fieldType == null || fieldType.isEmpty()) {
                throw new IllegalArgumentException("field type is required");
            }

            int end = fieldType.length();
            int dimensions = 0;
            while (end > 0 && fieldType.charAt(end - 1) == ']') {
                if (++dimensions >= MAX_VALUE_NESTING_DEPTH) {
                    throw new IllegalArgumentException(
                            "EIP-712 array nesting exceeds "
                                    + (MAX_VALUE_NESTING_DEPTH - 1) + " dimensions: " + fieldType);
                }
                int open = fieldType.lastIndexOf('[', end - 1);
                if (open < 0) {
                    throw new IllegalArgumentException("Invalid EIP-712 array type: " + fieldType);
                }
                String length = fieldType.substring(open + 1, end - 1);
                if (!length.isEmpty()) {
                    parsePositiveArrayLength(length, fieldType);
                }
                end = open;
            }
            String base = fieldType.substring(0, end);
            if (base.indexOf('[') >= 0 || base.indexOf(']') >= 0) {
                throw new IllegalArgumentException("Invalid EIP-712 array type: " + fieldType);
            }

            requireIdentifier("field type", base);
            if (isSupportedAtomicType(base) || types.containsKey(base)) {
                return;
            }
            throw new IllegalArgumentException("Unknown or unsupported EIP-712 type: " + fieldType);
        }

        private static int parsePositiveArrayLength(String value, String fieldType) {
            for (int i = 0; i < value.length(); i++) {
                char c = value.charAt(i);
                if (c < '0' || c > '9') {
                    throw new IllegalArgumentException("Invalid EIP-712 array type: " + fieldType);
                }
            }
            try {
                int length = Integer.parseInt(value);
                if (length <= 0 || !Integer.toString(length).equals(value)) {
                    throw new IllegalArgumentException(
                            "Fixed EIP-712 array length must be canonical and positive: " + fieldType);
                }
                return length;
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(
                        "Fixed EIP-712 array length is too large: " + fieldType, e);
            }
        }

        private static boolean isSupportedAtomicType(String type) {
            if (type.equals("address") || type.equals("bool") || type.equals("string")
                    || type.equals("bytes") || type.equals("trcToken")) {
                return true;
            }

            Matcher integer = INTEGER_TYPE.matcher(type);
            if (integer.matches()) {
                String width = integer.group(2);
                if (width.isEmpty()) return false;
                int bits = parseCanonicalDecimal(width, type);
                return bits >= 8 && bits <= 256 && bits % 8 == 0;
            }

            Matcher bytes = BYTES_TYPE.matcher(type);
            if (bytes.matches()) {
                String width = bytes.group(1);
                if (width.isEmpty()) return true;
                int size = parseCanonicalDecimal(width, type);
                return size >= 1 && size <= 32;
            }
            return false;
        }

        private static int parseCanonicalDecimal(String value, String type) {
            try {
                int parsed = Integer.parseInt(value);
                if (!Integer.toString(parsed).equals(value)) {
                    throw new IllegalArgumentException("Non-canonical EIP-712 type: " + type);
                }
                return parsed;
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid EIP-712 type: " + type, e);
            }
        }

        private static boolean isAtomicTypeName(String type) {
            return type != null && (type.equals("address") || type.equals("bool")
                    || type.equals("string") || type.equals("trcToken")
                    || INTEGER_TYPE.matcher(type).matches() || BYTES_TYPE.matcher(type).matches());
        }

        private static void requireIdentifier(String description, String value) {
            if (value == null || !IDENTIFIER.matcher(value).matches()) {
                throw new IllegalArgumentException(
                        "Invalid EIP-712 " + description + " identifier: " + value);
            }
        }
    }
}
