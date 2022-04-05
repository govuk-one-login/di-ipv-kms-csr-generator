package uk.gov.di.ipv.kmspublickeyops;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.jce.provider.ec.KmsECKeyFactory;
import software.amazon.awssdk.services.kms.jce.provider.ec.KmsECPublicKey;
import software.amazon.awssdk.services.kms.model.DescribeKeyRequest;
import software.amazon.awssdk.services.kms.model.DescribeKeyResponse;

@Command(name = "jwk", description = "Generates a JWK for a KMS EC P-256 public key")
public class JwkCommand implements Runnable{

    @Option(names = "--keyAlias", required = true, description = "Required: The KMS key alias for the key to generate a JWK for (including the 'alias/' prefix)")
    private String keyAlias;

    @Override
    public void run() {
        KmsClient client = KmsClient.create();

        DescribeKeyResponse describeKeyResponse = client.describeKey(
                DescribeKeyRequest.builder().keyId(keyAlias).build()
        );
        KmsECPublicKey publicKey = KmsECKeyFactory.getPublicKey(
                client,
                describeKeyResponse.keyMetadata().keyId()
        );

        System.out.println(
                new ECKey.Builder(Curve.P_256, publicKey).build().toPublicJWK().toJSONString()
        );
    }
}
