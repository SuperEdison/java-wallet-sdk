package io.github.superedison.web3.crypto.eip712;

import io.github.superedison.web3.crypto.hash.Keccak256;
import org.bouncycastle.jcajce.provider.digest.Keccak;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * EIP-712 / TIP-712 结构化数据编码器：把 {@link Eip712TypedData} 编码为 32 字节签名摘要。
 *
 * <p>算法（EIP-712，TIP-712 与之字节兼容）：
 * <pre>
 *   digest          = keccak256(0x19 0x01 ‖ domainSeparator ‖ hashStruct(message))
 *   domainSeparator = hashStruct(EIP712Domain, domain)
 *   hashStruct(s)   = keccak256(typeHash ‖ encodeData(s))
 *   typeHash        = keccak256(encodeType(typeOf(s)))
 *   encodeType      = 主类型定义在前，其余被引用类型按名称字母序拼接
 *   encodeData      = 各成员 enc 值（每个 32 字节）依序拼接
 * </pre>
 *
 * <p>唯一的链相关点是 {@code address} 的解析，通过构造时注入的 {@link AddressCodec} 处理
 * （EVM 0x-hex；TRON 剥 0x41 / base58）。{@code trcToken} 作为 TRON 扩展被识别并按 uint256 编码；
 * 非 TRON 链不声明该类型即可，无副作用。EIP-712 明确不含 {@code uint}/{@code int} 别名，故裸类型被拒绝。
 */
public final class Eip712Encoder {

    private static final int MAX_ENCODING_DEPTH = 128;
    private static final Pattern BYTES_N = Pattern.compile("^bytes(\\d{1,2})$");
    // 位宽必须显式给出：裸 uint/int 会与 ethers/tronweb 归一化后的 uint256/int256 产生不同 typeHash
    private static final Pattern UINT = Pattern.compile("^uint(\\d{1,3})$");
    private static final Pattern INT = Pattern.compile("^int(\\d{1,3})$");

    private final Map<String, List<Eip712TypedData.Field>> allTypes;
    private final String primaryType;
    private final Eip712Domain domain;
    private final Map<String, Object> message;
    private final AddressCodec addressCodec;

    /** 使用默认地址编解码器（0x-hex / 20-或-21字节）。 */
    public Eip712Encoder(Eip712TypedData data) {
        this(data, AddressCodec.DEFAULT);
    }

    public Eip712Encoder(Eip712TypedData data, AddressCodec addressCodec) {
        // 合并用户类型与自动构造的 EIP712Domain 类型，统一编码路径
        this.allTypes = new LinkedHashMap<>(data.types());
        this.allTypes.put(Eip712Domain.DOMAIN_TYPE_NAME, data.domain().presentFields());
        this.primaryType = data.primaryType();
        this.domain = data.domain();
        this.message = data.message();
        this.addressCodec = addressCodec;
    }

    /** 计算最终 32 字节签名摘要。 */
    public byte[] digest() {
        EncodingContext context = new EncodingContext();
        byte[] ds = hashStruct(Eip712Domain.DOMAIN_TYPE_NAME, domain.valueMap(), context, 0);
        byte[] hs = hashStruct(primaryType, message, context, 0);
        byte[] pre = new byte[2 + 32 + 32];
        pre[0] = 0x19;
        pre[1] = 0x01;
        System.arraycopy(ds, 0, pre, 2, 32);
        System.arraycopy(hs, 0, pre, 34, 32);
        return Keccak256.hash(pre);
    }

    public byte[] domainSeparator() {
        return hashStruct(
                Eip712Domain.DOMAIN_TYPE_NAME, domain.valueMap(), new EncodingContext(), 0);
    }

    // ==================== encodeType / typeHash ====================

    /** encodeType：主类型在前，其余被引用 struct 类型按名称字母序拼接。 */
    public String encodeType(String type) {
        TreeSet<String> deps = new TreeSet<>();
        collectDependencies(type, deps);
        deps.remove(type);
        StringBuilder sb = new StringBuilder(typeDefinition(type));
        for (String dep : deps) {
            sb.append(typeDefinition(dep));
        }
        return sb.toString();
    }

    private void collectDependencies(String type, TreeSet<String> found) {
        ArrayDeque<String> pending = new ArrayDeque<>();
        pending.push(type);
        while (!pending.isEmpty()) {
            String current = pending.pop();
            if (!allTypes.containsKey(current) || !found.add(current)) {
                continue;
            }
            for (Eip712TypedData.Field f : allTypes.get(current)) {
                String base = innermostType(f.type());
                if (allTypes.containsKey(base) && !found.contains(base)) {
                    pending.push(base);
                }
            }
        }
    }

    private String typeDefinition(String type) {
        StringBuilder sb = new StringBuilder(type).append('(');
        List<Eip712TypedData.Field> fields = allTypes.get(type);
        if (fields == null) {
            throw new IllegalArgumentException("Unknown struct type: " + type);
        }
        for (int i = 0; i < fields.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append(fields.get(i).type()).append(' ').append(fields.get(i).name());
        }
        return sb.append(')').toString();
    }

    public byte[] typeHash(String type) {
        return Keccak256.hash(strictUtf8(encodeType(type)));
    }

    // ==================== hashStruct / encodeData ====================

    public byte[] hashStruct(String type, Map<String, Object> value) {
        return hashStruct(type, value, new EncodingContext(), 0);
    }

    private byte[] hashStruct(
            String type, Map<String, Object> value, EncodingContext context, int depth) {
        List<Eip712TypedData.Field> fields = allTypes.get(type);
        if (fields == null) {
            throw new IllegalArgumentException("Unknown struct type: " + type);
        }
        if (value == null) {
            throw new IllegalArgumentException("null value for struct type " + type);
        }

        String cacheKey = "struct:" + type;
        byte[] cached = context.cached(value, cacheKey);
        if (cached != null) return cached;
        context.enter(value, depth);
        try {
            byte[] out = new byte[32 + 32 * fields.size()];
            System.arraycopy(typeHash(type), 0, out, 0, 32);
            int off = 32;
            for (Eip712TypedData.Field f : fields) {
                if (!value.containsKey(f.name())) {
                    throw new IllegalArgumentException(
                            "Missing value for field '" + f.name() + "' of type " + type);
                }
                System.arraycopy(
                        encodeValue(f.type(), value.get(f.name()), context, depth + 1),
                        0, out, off, 32);
                off += 32;
            }
            byte[] result = Keccak256.hash(out);
            context.cache(value, cacheKey, result);
            return result;
        } finally {
            context.exit(value);
        }
    }

    /** 把单个成员值编码为 32 字节。 */
    @SuppressWarnings("unchecked")
    public byte[] encodeValue(String type, Object value) {
        return encodeValue(type, value, new EncodingContext(), 0);
    }

    @SuppressWarnings("unchecked")
    private byte[] encodeValue(
            String type, Object value, EncodingContext context, int depth) {
        if (value == null) {
            throw new IllegalArgumentException("null value for type " + type);
        }
        // 数组：keccak256(逐元素 enc 拼接)
        if (type.endsWith("]")) {
            String cacheKey = "array:" + type;
            byte[] cached = context.cached(value, cacheKey);
            if (cached != null) return cached;
            context.enter(value, depth);
            try {
                String base = stripOneArrayLevel(type);
                String lenStr = type.substring(type.lastIndexOf('[') + 1, type.length() - 1);
                List<Object> elems = asList(value);
                if (!lenStr.isEmpty() && Integer.parseInt(lenStr) != elems.size()) {
                    throw new IllegalArgumentException(
                            "Fixed array length mismatch for " + type
                                    + ": expected " + lenStr + ", got " + elems.size());
                }
                Keccak.Digest256 arrayDigest = new Keccak.Digest256();
                for (int i = 0; i < elems.size(); i++) {
                    arrayDigest.update(encodeValue(base, elems.get(i), context, depth + 1));
                }
                byte[] result = arrayDigest.digest();
                context.cache(value, cacheKey, result);
                return result;
            } finally {
                context.exit(value);
            }
        }
        // 嵌套 struct：hashStruct
        if (allTypes.containsKey(type)) {
            if (!(value instanceof Map<?, ?>)) {
                throw new IllegalArgumentException(
                        "Struct type " + type + " requires a Map, got " + value.getClass());
            }
            return hashStruct(type, (Map<String, Object>) value, context, depth);
        }
        // 原子/动态类型
        switch (type) {
            case "string":
                return Keccak256.hash(strictUtf8((String) value));
            case "bytes":
                return Keccak256.hash(toBytes(value));
            case "bool":
                return bool32(value);
            case "address":
                return encodeAddress(value);
            case "trcToken": { // TRON 扩展：按 uint256 编码
                BigInteger tv = requireUnsigned(toBigInteger(value), type);
                checkIntegerWidth(tv, 256, false, type);
                return toBytes32(tv);
            }
            default:
                // fall through to regex-matched types
        }
        Matcher mBytes = BYTES_N.matcher(type);
        if (mBytes.matches()) {
            return encodeFixedBytes(Integer.parseInt(mBytes.group(1)), value);
        }
        Matcher mUint = UINT.matcher(type);
        if (mUint.matches()) {
            BigInteger v = requireUnsigned(toBigInteger(value), type);
            checkIntegerWidth(v, Integer.parseInt(mUint.group(1)), false, type);
            return toBytes32(v);
        }
        Matcher mInt = INT.matcher(type);
        if (mInt.matches()) {
            BigInteger v = toBigInteger(value);
            checkIntegerWidth(v, Integer.parseInt(mInt.group(1)), true, type);
            return toBytes32(v);
        }
        throw new IllegalArgumentException("Unsupported EIP-712 type: " + type);
    }

    // ==================== 类型转换辅助 ====================

    private byte[] encodeAddress(Object value) {
        byte[] body = addressCodec.toAddress20(value);
        if (body.length != 20) {
            throw new IllegalArgumentException("AddressCodec must return 20 bytes, got " + body.length);
        }
        byte[] out = new byte[32];
        System.arraycopy(body, 0, out, 12, 20); // 左填充 = uint160
        return out;
    }

    private static byte[] encodeFixedBytes(int n, Object value) {
        if (n < 1 || n > 32) {
            throw new IllegalArgumentException("bytesN out of range: bytes" + n);
        }
        byte[] b = toBytes(value);
        if (b.length != n) {
            throw new IllegalArgumentException("bytes" + n + " requires exactly " + n + " bytes, got " + b.length);
        }
        byte[] out = new byte[32]; // 左对齐、右侧补零
        System.arraycopy(b, 0, out, 0, n);
        return out;
    }

    private static byte[] bool32(Object value) {
        // 严格解析：绝不把非 "true" 的值静默当成 false（那会对错误的消息产出有效签名）
        boolean b;
        if (value instanceof Boolean bool) {
            b = bool;
        } else if (value instanceof Number n) {
            b = numericBool(n);
        } else if (value instanceof String s) {
            String t = s.trim().toLowerCase(Locale.ROOT);
            if (t.equals("true") || t.equals("1")) b = true;
            else if (t.equals("false") || t.equals("0")) b = false;
            else throw new IllegalArgumentException("bool string must be true/false/0/1, got: " + s);
        } else {
            throw new IllegalArgumentException("Unsupported bool value: " + value.getClass());
        }
        byte[] out = new byte[32];
        out[31] = (byte) (b ? 1 : 0);
        return out;
    }

    private static boolean numericBool(Number value) {
        if (value instanceof BigInteger bi) {
            if (bi.equals(BigInteger.ONE)) return true;
            if (bi.equals(BigInteger.ZERO)) return false;
        } else if (value instanceof BigDecimal bd) {
            if (bd.compareTo(BigDecimal.ONE) == 0) return true;
            if (bd.compareTo(BigDecimal.ZERO) == 0) return false;
        } else if (value instanceof Byte || value instanceof Short
                || value instanceof Integer || value instanceof Long) {
            long l = value.longValue();
            if (l == 1) return true;
            if (l == 0) return false;
        } else if (value instanceof Float f) {
            if (Float.isFinite(f) && f == 1.0f) return true;
            if (Float.isFinite(f) && f == 0.0f) return false;
        } else if (value instanceof Double d) {
            if (Double.isFinite(d) && d == 1.0d) return true;
            if (Double.isFinite(d) && d == 0.0d) return false;
        } else {
            throw new IllegalArgumentException("Unsupported bool numeric value: " + value.getClass());
        }
        throw new IllegalArgumentException("bool numeric must be exactly 0 or 1, got: " + value);
    }

    /** 校验整数取值落在声明的位宽内（EIP-712/ABI：N 为 8..256 的 8 的倍数）。 */
    private static void checkIntegerWidth(BigInteger v, int bits, boolean signed, String type) {
        if (bits < 8 || bits > 256 || bits % 8 != 0) {
            throw new IllegalArgumentException("Invalid integer width: " + type);
        }
        if (signed) {
            BigInteger limit = BigInteger.ONE.shiftLeft(bits - 1); // 2^(bits-1)
            if (v.compareTo(limit.negate()) < 0 || v.compareTo(limit) >= 0) {
                throw new IllegalArgumentException(type + " value out of range: " + v);
            }
        } else if (v.bitLength() > bits) { // v >= 2^bits
            throw new IllegalArgumentException(type + " value out of range: " + v);
        }
    }

    /**
     * BigInteger → 32 字节大端；负数按二进制补码符号扩展。
     *
     * @throws IllegalArgumentException 当值无法以 uint256 或 int256 表示时
     */
    public static byte[] toBytes32(BigInteger v) {
        if (v.signum() >= 0 && v.bitLength() > 256) {
            throw new IllegalArgumentException("Value does not fit uint256: " + v);
        }
        BigInteger int256Min = BigInteger.ONE.shiftLeft(255).negate();
        if (v.signum() < 0 && v.compareTo(int256Min) < 0) {
            throw new IllegalArgumentException("Value does not fit int256: " + v);
        }
        byte[] out = new byte[32];
        byte[] b = v.toByteArray(); // 二进制补码、大端，可能含符号字节或前导零
        if (b.length > 32) {
            System.arraycopy(b, b.length - 32, out, 0, 32); // 取低 32 字节
        } else {
            System.arraycopy(b, 0, out, 32 - b.length, b.length);
            if (v.signum() < 0) {
                for (int i = 0; i < 32 - b.length; i++) {
                    out[i] = (byte) 0xFF;
                }
            }
        }
        return out;
    }

    private static BigInteger requireUnsigned(BigInteger v, String type) {
        if (v.signum() < 0) {
            throw new IllegalArgumentException(type + " must be non-negative, got " + v);
        }
        return v;
    }

    private static BigInteger toBigInteger(Object v) {
        if (v instanceof BigInteger bi) return bi;
        if (v instanceof Long l) return BigInteger.valueOf(l);
        if (v instanceof Integer i) return BigInteger.valueOf(i);
        if (v instanceof Short sh) return BigInteger.valueOf(sh);
        if (v instanceof Byte by) return BigInteger.valueOf(by);
        if (v instanceof String s) {
            String t = s.trim();
            if (t.startsWith("0x") || t.startsWith("0X")) {
                String digits = t.substring(2);
                if (digits.isEmpty()) {
                    throw new IllegalArgumentException("Hex integer must contain at least one digit: " + s);
                }
                for (int i = 0; i < digits.length(); i++) {
                    hexNibble(digits.charAt(i));
                }
                return new BigInteger(digits, 16);
            }
            int digitStart = (t.startsWith("+") || t.startsWith("-")) ? 1 : 0;
            if (digitStart == t.length()) {
                throw new IllegalArgumentException(
                        "Decimal integer must contain at least one digit: " + s);
            }
            for (int i = digitStart; i < t.length(); i++) {
                char c = t.charAt(i);
                if (c < '0' || c > '9') {
                    throw new IllegalArgumentException(
                            "Invalid decimal integer character: '" + c + "'");
                }
            }
            return new BigInteger(t);
        }
        throw new IllegalArgumentException("Cannot convert to integer: " + v.getClass());
    }

    private static byte[] toBytes(Object v) {
        if (v instanceof byte[] b) return b;
        if (v instanceof String s) return hexToBytes(s);
        throw new IllegalArgumentException("Cannot convert to bytes: " + v.getClass());
    }

    @SuppressWarnings("unchecked")
    private static List<Object> asList(Object v) {
        if (v instanceof List) return (List<Object>) v;
        if (v instanceof Object[] arr) return List.of(arr);
        throw new IllegalArgumentException("Array type requires a List or Object[], got " + v.getClass());
    }

    private static byte[] hexToBytes(String hex) {
        String h = hex.startsWith("0x") || hex.startsWith("0X") ? hex.substring(2) : hex;
        if ((h.length() & 1) != 0) {
            throw new IllegalArgumentException("Hex string must have even length: " + hex);
        }
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++) {
            // 逐 nibble 解析并严格校验字符，拒绝 +/- 等被 Integer.parseInt 静默接受的符号
            out[i] = (byte) ((hexNibble(h.charAt(i * 2)) << 4) | hexNibble(h.charAt(i * 2 + 1)));
        }
        return out;
    }

    private static byte[] strictUtf8(String value) {
        try {
            ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(value));
            byte[] out = new byte[encoded.remaining()];
            encoded.get(out);
            return out;
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("string contains invalid UTF-16", e);
        }
    }

    private static int hexNibble(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        throw new IllegalArgumentException("Invalid hex character: '" + c + "'");
    }

    private static String stripOneArrayLevel(String type) {
        return type.substring(0, type.lastIndexOf('['));
    }

    private static String innermostType(String type) {
        String t = type;
        while (t.endsWith("]")) {
            t = t.substring(0, t.lastIndexOf('['));
        }
        return t;
    }

    private static final class EncodingContext {
        private final IdentityHashMap<Object, Boolean> ancestors = new IdentityHashMap<>();
        private final IdentityHashMap<Object, Map<String, byte[]>> cache = new IdentityHashMap<>();

        byte[] cached(Object value, String type) {
            Map<String, byte[]> byType = cache.get(value);
            return byType == null ? null : byType.get(type);
        }

        void cache(Object value, String type, byte[] encoded) {
            cache.computeIfAbsent(value, ignored -> new LinkedHashMap<>()).put(type, encoded);
        }

        void enter(Object value, int depth) {
            if (depth >= MAX_ENCODING_DEPTH) {
                throw new IllegalArgumentException(
                        "EIP-712 value nesting exceeds " + MAX_ENCODING_DEPTH + " containers");
            }
            if (ancestors.put(value, Boolean.TRUE) != null) {
                throw new IllegalArgumentException("Cyclic EIP-712 values are not supported");
            }
        }

        void exit(Object value) {
            ancestors.remove(value);
        }
    }
}
