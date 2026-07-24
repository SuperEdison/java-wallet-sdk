package io.github.superedison.web3.crypto.eip712;

/**
 * 地址值 → 20 字节地址主体的解析策略（编码器随后左填充到 32 字节 = uint160）。
 *
 * <p>各链注入自己的实现以支持链特有的地址表示：EVM 用 {@link #DEFAULT}（0x-hex / 20 字节），
 * TRON 额外支持 base58（{@code T...}）与 0x41 前缀剥离。将地址这一唯一的链相关点做成可插拔，
 * 使 {@link Eip712Encoder} 的其余编码逻辑对 EIP-712 / TIP-712 完全通用、只维护一份。
 */
@FunctionalInterface
public interface AddressCodec {

    /** 解析为 20 字节地址主体。 */
    byte[] toAddress20(Object value);

    /**
     * 默认实现：接受 {@code byte[]}（20 字节，或 21 字节且以 0x41 开头则剥离）与十六进制 {@code String}
     * （含/不含 0x；40 位 = 20 字节；42 位且以 41 开头则剥离到 20 字节）。EVM 0x-hex 地址直接适用。
     */
    AddressCodec DEFAULT = value -> {
        byte[] raw;
        if (value instanceof byte[] b) {
            raw = b;
        } else if (value instanceof String s) {
            raw = hexToBytes(s);
        } else {
            throw new IllegalArgumentException("Unsupported address value: " + value.getClass());
        }
        if (raw.length == 21 && (raw[0] & 0xFF) == 0x41) {
            byte[] body = new byte[20];
            System.arraycopy(raw, 1, body, 0, 20);
            return body;
        }
        if (raw.length == 20) {
            return raw;
        }
        throw new IllegalArgumentException(
                "Address must be 20 bytes, or 21 with 0x41 prefix; got " + raw.length);
    };

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

    private static int hexNibble(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        throw new IllegalArgumentException("Invalid hex character: '" + c + "'");
    }
}
