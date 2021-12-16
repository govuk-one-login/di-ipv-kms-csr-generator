package uk.gov.di.ipv.kmscsrgen;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.jce.provider.KmsProvider;
import software.amazon.awssdk.services.kms.jce.provider.rsa.KmsRSAKeyFactory;
import software.amazon.awssdk.services.kms.jce.provider.signature.KmsSigningAlgorithm;
import software.amazon.awssdk.services.kms.jce.util.csr.CsrGenerator;
import software.amazon.awssdk.services.kms.jce.util.csr.CsrInfo;
import software.amazon.awssdk.services.kms.model.DescribeKeyRequest;
import software.amazon.awssdk.services.kms.model.DescribeKeyResponse;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.security.KeyPair;
import java.security.Security;
import java.util.concurrent.Callable;

@Command(name = "generate a CSR", description = "Generates a CSR signed by KSM")
public class KmsCsrGenerator implements Callable<Integer> {
    @Option(names = "--cn", required = true, description = "Required: The common name to use on the CSR")
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

    @Option(names = "--keyAlias", required = true, description = "Required: The KMS key alias to create a CSR with (including the 'alias/' prefix)")
    private String keyAlias;

    @Option(names = "--outfile", description = "Default: <common name>.csr")
    private String outfile;

    public static void main(String... args) {
        int exitCode = new CommandLine(new KmsCsrGenerator()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() throws Exception {
        KmsClient client = KmsClient.create();

        DescribeKeyRequest describeKeyRequest = DescribeKeyRequest.builder().keyId(keyAlias).build();
        DescribeKeyResponse describeKeyResponse = client.describeKey(describeKeyRequest);
        String keyId = describeKeyResponse.keyMetadata().keyId();

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
        KeyPair keyPair = KmsRSAKeyFactory.getKeyPair(client, keyId);
        KmsSigningAlgorithm kmsSigningAlgorithm = KmsSigningAlgorithm.RSASSA_PKCS1_V1_5_SHA_256;
        String csr = CsrGenerator.generate(keyPair, csrInfo, kmsSigningAlgorithm);

        // Write the csr to file
        if (outfile == null) {
            outfile = commonName;
        }
        BufferedWriter writer = new BufferedWriter(new FileWriter(outfile + ".csr"));
        writer.write(csr);
        writer.close();

        System.out.println(csr);

        return 0;
    }
}
