package io.github.superedison.web3.crypto.ecc;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("Ed25519 signer lifecycle regression tests")
class Ed25519SignerTest {

    private static final byte[] PRIVATE_KEY = HexFormat.of().parseHex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    private static final byte[] PUBLIC_KEY = HexFormat.of().parseHex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    private static final byte[] EMPTY_MESSAGE_SIGNATURE = HexFormat.of().parseHex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                    + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

    @Test
    @DisplayName("signing still matches RFC 8032 after removing persistent BC private parameters")
    void matchesRfc8032Vector() {
        try (Ed25519Signer signer = new Ed25519Signer(PRIVATE_KEY)) {
            assertThat(signer.getPublicKey()).isEqualTo(PUBLIC_KEY);
            assertThat(signer.signRaw(new byte[0])).isEqualTo(EMPTY_MESSAGE_SIGNATURE);
            assertThat(Ed25519Signer.verify(
                    new byte[0], EMPTY_MESSAGE_SIGNATURE, PUBLIC_KEY)).isTrue();
        }
    }

    @Test
    @DisplayName("destroy wipes the sole retained private-key array and blocks use")
    void destroyWipesControlledPrivateKey() throws ReflectiveOperationException {
        Ed25519Signer signer = new Ed25519Signer(PRIVATE_KEY);
        Field field = Ed25519Signer.class.getDeclaredField("privateKey");
        field.setAccessible(true);
        byte[] retainedPrivateKey = (byte[]) field.get(signer);

        signer.destroy();

        assertThat(retainedPrivateKey).containsOnly((byte) 0);
        assertThatThrownBy(() -> signer.signRaw(new byte[0]))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(signer::getPublicKey)
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> signer.verify(new byte[0], EMPTY_MESSAGE_SIGNATURE))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("null messages are rejected consistently")
    void rejectsNullMessage() {
        try (Ed25519Signer signer = new Ed25519Signer(PRIVATE_KEY)) {
            assertThatThrownBy(() -> signer.sign(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("cannot be null");
            assertThatThrownBy(() -> signer.signRaw(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("cannot be null");
        }
    }
}
