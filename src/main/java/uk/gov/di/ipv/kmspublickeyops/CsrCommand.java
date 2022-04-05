package uk.gov.di.ipv.kmspublickeyops;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.jce.provider.KmsProvider;
import software.amazon.awssdk.services.kms.jce.provider.rsa.KmsRSAKeyFactory;
import software.amazon.awssdk.services.kms.jce.provider.signature.KmsSigningAlgorithm;
import software.amazon.awssdk.services.kms.jce.util.crt.SelfSignedCrtGenerator;
import software.amazon.awssdk.services.kms.jce.util.csr.CsrGenerator;
import software.amazon.awssdk.services.kms.jce.util.csr.CsrInfo;
import software.amazon.awssdk.services.kms.model.DescribeKeyRequest;
import software.amazon.awssdk.services.kms.model.DescribeKeyResponse;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.Security;

@Command(name = "csr", description = "Generates a CSR or self-signed certificate signed by KSM")
public class CsrCommand implements Runnable {
    private static final KmsSigningAlgorithm kmsSigningAlgorithm = KmsSigningAlgorithm.RSASSA_PKCS1_V1_5_SHA_256;
    private static final String csrExtension = ".csr";
    private static final String crtExtension = ".crt";

    @Option(names = "--cn", required = true, description = "Required: The common name to use")
    private String commonName;

    @Option(names = "--ou", defaultValue = "GDS", description = "Default: ${DEFAULT-VALUE}")
    private String organisationalUnit;

    @Option(names = "--o", defaultValue = "Cabinet Office", description = "Default: ${DEFAULT-VALUE}")
    private String organisation;

    @Option(names = "--l", defaultValue = "London", description = "Default: ${DEFAULT-VALUE}")
    private String location;

    @Option(names = "--st", defaultValue = "Greater London", description = "Default: ${DEFAULT-VALUE}")
    private String state;

    @Option(names = "--c", defaultValue = "UK", description = "Default: ${DEFAULT-VALUE}")
    private String country;

    @Option(names = "--keyAlias", required = true, description = "Required: The KMS key alias for the key to sign with (including the 'alias/' prefix)")
    private String keyAlias;

    @Option(names = "--outfile", description = "Default: <common name>.csr")
    private String outfile;

    @Option(names = "--self-signed", description = "Generate a self-signed certificate with this number of days validity")
    private int selfSignedValidity;

    @Override
    public void run() {
        KmsClient client = KmsClient.create();

        DescribeKeyRequest describeKeyRequest = DescribeKeyRequest.builder().keyId(keyAlias).build();
        DescribeKeyResponse describeKeyResponse = client.describeKey(describeKeyRequest);
        String keyId = describeKeyResponse.keyMetadata().keyId();

        KeyPair keyPair = KmsRSAKeyFactory.getKeyPair(client, keyId);

        KmsProvider kmsProvider = new KmsProvider(client);
        Security.addProvider(kmsProvider);

        // Create CSR
        CsrInfo csrInfo =
                CsrInfo.builder()
                        .cn(commonName)
                        .ou(organisationalUnit)
                        .o(organisation)
                        .l(location)
                        .st(state)
                        .c(country)
                        .build();


        // Actually create and sign the CSR
        String csr = CsrGenerator.generate(keyPair, csrInfo, kmsSigningAlgorithm);
        String content = csr;
        String extension = csrExtension;

        // Generate a self-signed certificate if requested
        if (selfSignedValidity > 0) {
            content = SelfSignedCrtGenerator.generate(keyPair, csr, kmsSigningAlgorithm, selfSignedValidity);
            extension = crtExtension;
        }

        // Write the content to file
        if (outfile == null) {
            outfile = commonName;
        }
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outfile + extension))) {
            writer.write(content);
        } catch (IOException e) {
            throw new RuntimeException(e.getMessage());
        }
        System.out.println(content);
    }
}
