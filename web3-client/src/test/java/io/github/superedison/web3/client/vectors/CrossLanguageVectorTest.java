package io.github.superedison.web3.client.vectors;

import io.github.superedison.web3.chain.evm.internal.EvmSignature;
import io.github.superedison.web3.chain.spi.signing.Secp256k1VNormalizer;
import io.github.superedison.web3.chain.tron.internal.TronSignature;
import io.github.superedison.web3.client.derive.AccountDeriver;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("跨语言一致性向量测试")
class CrossLanguageVectorTest {

    @Test
    @DisplayName("secp256k1 v 归一化向量应一致")
    void secp256k1VNormalizationVectorsShouldMatch() throws IOException {
        List<String> lines = readVectorLines("secp256k1_v_normalization.csv");

        for (String line : lines) {
            String[] parts = line.split(",");
            long inputV = Long.parseLong(parts[0]);
            int expectedRecoveryId = Integer.parseInt(parts[1]);
            int expectedLegacyV = Integer.parseInt(parts[2]);
            long chainId = Long.parseLong(parts[3]);
            long expectedEip155V = Long.parseLong(parts[4]);

            assertThat(Secp256k1VNormalizer.toRecoveryId(inputV)).isEqualTo(expectedRecoveryId);
            assertThat(Secp256k1VNormalizer.toLegacyV(inputV)).isEqualTo(expectedLegacyV);
            assertThat(Secp256k1VNormalizer.toEip155V(inputV, chainId)).isEqualTo(expectedEip155V);

            EvmSignature evmSig = EvmSignature.fromCompact(buildCompactSignature(inputV));
            assertThat(evmSig.getRecoveryId()).isEqualTo(expectedRecoveryId);
            assertThat(evmSig.toEip155(chainId).getV()).isEqualTo(expectedEip155V);

            TronSignature tronSig = TronSignature.fromCompact(buildCompactSignature(inputV));
            assertThat(tronSig.getV()).isEqualTo(expectedLegacyV);
            assertThat(tronSig.getRecoveryId()).isEqualTo(expectedRecoveryId);
        }
    }

    @Test
    @DisplayName("userId 到 accountIndex 映射向量应一致")
    void accountIndexVectorsShouldMatch() throws IOException {
        List<String> lines = readVectorLines("account_index_mapping.csv");

        for (String line : lines) {
            String[] parts = line.split(",");
            String userId = parts[0];
            int expectedV1 = Integer.parseInt(parts[1]);
            assertThat(AccountDeriver.userIdToAccountIndex(userId)).isEqualTo(expectedV1);
        }
    }

    @Test
    @DisplayName("v 归一化应拒绝非法参数")
    void invalidVShouldThrow() {
        assertThatThrownBy(() -> Secp256k1VNormalizer.toRecoveryId(-1))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Secp256k1VNormalizer.toEip155V(27, -1))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static byte[] buildCompactSignature(long inputV) {
        byte[] sig = new byte[65];
        sig[31] = 1;
        sig[63] = 2;
        sig[64] = (byte) inputV;
        return sig;
    }

    private static List<String> readVectorLines(String fileName) throws IOException {
        String resourcePath = "/test-vectors/" + fileName;
        try (InputStream stream = CrossLanguageVectorTest.class.getResourceAsStream(resourcePath)) {
            if (stream == null) {
                throw new IllegalStateException("Vector resource not found: " + resourcePath);
            }
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
                return reader.lines()
                        .skip(1)
                        .map(String::trim)
                        .filter(line -> !line.isEmpty())
                        .toList();
            }
        }
    }
}
