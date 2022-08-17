package uk.gov.di.ipv.kmspublickeyops;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.jce.provider.ec.KmsECKeyFactory;
import software.amazon.awssdk.services.kms.jce.provider.rsa.KmsRSAKeyFactory;
import software.amazon.awssdk.services.kms.model.DescribeKeyRequest;
import software.amazon.awssdk.services.kms.model.DescribeKeyResponse;
import software.amazon.awssdk.services.kms.model.KeySpec;

import java.text.ParseException;

@Command(name = "jwk", description = "Generates a JWK for a KMS EC P-256 or RSA-2048 public key")
public class JwkCommand implements Runnable {

    @Option(names = "--keyAlias", required = true, description = "Required: The KMS key alias for the key to generate a JWK for (including the 'alias/' prefix)")
    private String keyAlias;

    @Option(names = "--keyUse", required = true, description = "Required: The intended use for the key")
    private String keyUse;

    @Override
    public void run() {
        KmsClient client = KmsClient.create();

        DescribeKeyResponse describeKeyResponse = client.describeKey(
                DescribeKeyRequest.builder().keyId(keyAlias).build()
        );

        String publicJwk;
        KeySpec keySpec = describeKeyResponse.keyMetadata().keySpec();

        try {
        switch (keySpec) {
            case ECC_NIST_P256:
                publicJwk = new ECKey.Builder(Curve.P_256, KmsECKeyFactory.getPublicKey(
                        client,
                        describeKeyResponse.keyMetadata().keyId()
                )).keyUse(KeyUse.parse(keyUse)).build().toPublicJWK().toJSONString();
                break;
            case RSA_2048:
                publicJwk = new RSAKey.Builder(KmsRSAKeyFactory.getPublicKey(
                        client,
                        describeKeyResponse.keyMetadata().keyId()
                )).keyUse(KeyUse.parse(keyUse)).build().toPublicJWK().toJSONString();
                break;
            default:
                throw new RuntimeException(String.format("Unsupported KeySpec: %s", keySpec));
        }

        } catch (ParseException e) {
            throw new RuntimeException(String.format("Unsupported key use: %s", keyUse));
        }

        System.out.println(publicJwk);
    }
}
