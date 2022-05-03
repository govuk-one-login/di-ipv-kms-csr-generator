package uk.gov.di.ipv.kmspublickeyops;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.jce.provider.ec.KmsECKeyFactory;
import software.amazon.awssdk.services.kms.jce.provider.rsa.KmsRSAKeyFactory;
import software.amazon.awssdk.services.kms.model.DescribeKeyRequest;
import software.amazon.awssdk.services.kms.model.DescribeKeyResponse;
import software.amazon.awssdk.services.kms.model.KeySpec;

@Command(name = "jwk", description = "Generates a JWK for a KMS EC P-256 or RSA-2048 public key")
public class JwkCommand implements Runnable {

    @Option(names = "--keyAlias", required = true, description = "Required: The KMS key alias for the key to generate a JWK for (including the 'alias/' prefix)")
    private String keyAlias;

    @Override
    public void run() {
        KmsClient client = KmsClient.create();

        DescribeKeyResponse describeKeyResponse = client.describeKey(
                DescribeKeyRequest.builder().keyId(keyAlias).build()
        );

        String publicJwk;
        KeySpec keySpec = describeKeyResponse.keyMetadata().keySpec();

        switch (keySpec) {
            case ECC_NIST_P256:
                publicJwk = new ECKey.Builder(Curve.P_256, KmsECKeyFactory.getPublicKey(
                        client,
                        describeKeyResponse.keyMetadata().keyId()
                )).build().toPublicJWK().toJSONString();
                break;
            case RSA_2048:
                publicJwk = new RSAKey.Builder(KmsRSAKeyFactory.getPublicKey(
                        client,
                        describeKeyResponse.keyMetadata().keyId()
                )).build().toPublicJWK().toJSONString();
                break;
            default:
                throw new RuntimeException(String.format("Unsupported KeySpec: %s", keySpec));
        }

        System.out.println(publicJwk);
    }
}
