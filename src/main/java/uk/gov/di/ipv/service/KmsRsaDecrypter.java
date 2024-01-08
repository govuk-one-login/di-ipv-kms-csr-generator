package uk.gov.di.ipv.service;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.jca.JWEJCAContext;
import com.nimbusds.jose.util.Base64URL;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec;

import javax.crypto.spec.SecretKeySpec;
import java.util.Objects;
import java.util.Set;

import static com.nimbusds.jose.JWEAlgorithm.RSA_OAEP_256;

public class KmsRsaDecrypter implements JWEDecrypter {
    private static final Set<JWEAlgorithm> SUPPORTED_ALGORITHMS = Set.of(JWEAlgorithm.RSA_OAEP_256);
    private static final Set<EncryptionMethod> SUPPORTED_ENCRYPTION_METHODS =
            Set.of(EncryptionMethod.A256GCM);

    private final KmsClient kmsClient;
    private final String keyId;
    private final JWEJCAContext jwejcaContext = new JWEJCAContext();

    public KmsRsaDecrypter(String keyId) {
        this.kmsClient = KmsClient.create();
        this.keyId = keyId;
    }

    @Override
    public byte[] decrypt(
            JWEHeader header,
            Base64URL encryptedKey,
            Base64URL iv,
            Base64URL cipherText,
            Base64URL authTag)
            throws JOSEException {
        if (Objects.isNull(encryptedKey)) {
            throw new JOSEException("Missing JWE encrypted key");
        }

        if (Objects.isNull(iv)) {
            throw new JOSEException("Missing JWE initialization vector (IV)");
        }

        if (Objects.isNull(authTag)) {
            throw new JOSEException("Missing JWE authentication tag");
        }

        JWEAlgorithm alg = header.getAlgorithm();

        if (!SUPPORTED_ALGORITHMS.contains(alg)) {
            throw new JOSEException(
                    AlgorithmSupportMessage.unsupportedJWEAlgorithm(alg, supportedJWEAlgorithms()));
        }

        DecryptRequest decryptRequest = DecryptRequest.builder()
                .keyId(keyId)
                .ciphertextBlob(SdkBytes.fromByteArray(encryptedKey.decode()))
                .encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256)
                .build();

        DecryptResponse decryptResponse = kmsClient.decrypt(decryptRequest);

        SecretKeySpec contentEncryptionKey =
                new SecretKeySpec(decryptResponse.plaintext().asByteArray(), "AES");

        return ContentCryptoProvider.decrypt(
                header, encryptedKey, iv, cipherText, authTag, contentEncryptionKey, jwejcaContext);
    }

    @Override
    public Set<JWEAlgorithm> supportedJWEAlgorithms() {
        return Set.of(RSA_OAEP_256);
    }

    @Override
    public Set<EncryptionMethod> supportedEncryptionMethods() {
        return SUPPORTED_ENCRYPTION_METHODS;
    }

    @Override
    public JWEJCAContext getJCAContext() {
        return jwejcaContext;
    }
}
