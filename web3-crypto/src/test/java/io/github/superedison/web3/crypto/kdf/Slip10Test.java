package io.github.superedison.web3.crypto.kdf;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("SLIP-0010 regression tests")
class Slip10Test {

    private static final byte[] VECTOR_SEED =
            HexFormat.of().parseHex("000102030405060708090a0b0c0d0e0f");
    private static final String MASTER_KEY =
            "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7";
    private static final String MASTER_CHAIN_CODE =
            "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb";
    private static final String FIRST_HARDENED_KEY =
            "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3";
    private static final String FIRST_HARDENED_CHAIN_CODE =
            "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69";

    @Test
    @DisplayName("master key matches the official Ed25519 test vector")
    void derivesOfficialMasterVector() {
        try (Slip10.ExtendedKey master =
                     Slip10.masterKeyFromSeed(VECTOR_SEED, Slip10.Curve.ED25519)) {
            assertThat(HexFormat.of().formatHex(master.getKey())).isEqualTo(MASTER_KEY);
            assertThat(HexFormat.of().formatHex(master.getChainCode())).isEqualTo(MASTER_CHAIN_CODE);
        }
    }

    @Test
    @DisplayName("child key remains intact after temporary derivation buffers are wiped")
    void derivesOfficialFirstHardenedChildVector() {
        try (Slip10.ExtendedKey master =
                     Slip10.masterKeyFromSeed(VECTOR_SEED, Slip10.Curve.ED25519);
             Slip10.ExtendedKey child = Slip10.deriveChild(master, 0x80000000)) {
            assertThat(HexFormat.of().formatHex(child.getKey())).isEqualTo(FIRST_HARDENED_KEY);
            assertThat(HexFormat.of().formatHex(child.getChainCode()))
                    .isEqualTo(FIRST_HARDENED_CHAIN_CODE);
            assertThat(child.getPathString()).isEqualTo("m/0'");
        }
    }

    @Test
    @DisplayName("root path returns an independent key object")
    void rootPathReturnsIndependentCopy() {
        try (Slip10.ExtendedKey master =
                     Slip10.masterKeyFromSeed(VECTOR_SEED, Slip10.Curve.ED25519);
             Slip10.ExtendedKey root = Slip10.derivePath(master, "m")) {

            assertThat(root).isNotSameAs(master);
            assertThat(root.getKey()).isEqualTo(master.getKey());

            root.destroy();
            assertThat(master.isDestroyed()).isFalse();
            assertThat(HexFormat.of().formatHex(master.getKey())).isEqualTo(MASTER_KEY);
        }
    }

    @Test
    @DisplayName("destroyed master key cannot be copied, read, or derived")
    void rejectsDestroyedMasterKey() {
        Slip10.ExtendedKey master =
                Slip10.masterKeyFromSeed(VECTOR_SEED, Slip10.Curve.ED25519);
        master.destroy();

        assertThatThrownBy(() -> Slip10.derivePath(master, "m"))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> Slip10.derivePath(master, null))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> Slip10.deriveChild(master, 0x80000000))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(master::getKey).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(master::getChainCode).isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("all path segments are validated before Ed25519 derivation")
    void rejectsAnyNonHardenedPathSegment() {
        try (Slip10.ExtendedKey master =
                     Slip10.masterKeyFromSeed(VECTOR_SEED, Slip10.Curve.ED25519)) {
            assertThatThrownBy(() -> Slip10.derivePath(master, "m/44'/501'/0"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("only supports hardened derivation");

            try (Slip10.ExtendedKey valid = Slip10.derivePath(master, "m/44'/501'/0'")) {
                assertThat(valid.depth()).isEqualTo(3);
                assertThat(valid.getPathString()).isEqualTo("m/44'/501'/0'");
            }
        }
    }

    @Test
    @DisplayName("extended-key entry points reject invalid curve and key material")
    void rejectsInvalidExtendedKeyMaterial() {
        byte[] validKey = HexFormat.of().parseHex(MASTER_KEY);
        byte[] validChainCode = HexFormat.of().parseHex(MASTER_CHAIN_CODE);

        assertThatThrownBy(() -> Slip10.masterKeyFromSeed(VECTOR_SEED, null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new Slip10.ExtendedKey(
                null, validKey, validChainCode, null, 0))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new Slip10.ExtendedKey(
                Slip10.Curve.ED25519, new byte[31], validChainCode, null, 0))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new Slip10.ExtendedKey(
                Slip10.Curve.ED25519, validKey, new byte[31], null, 0))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
