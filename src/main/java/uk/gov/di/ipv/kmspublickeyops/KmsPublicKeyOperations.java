package uk.gov.di.ipv.kmspublickeyops;

import picocli.CommandLine;
import picocli.CommandLine.Command;


@Command(name = "KMS public key operations",
        description = "Generates a CSR or self-signed certificate signed by KSM",
        subcommands = {  CsrCommand.class, JwkCommand.class, CommandLine.HelpCommand.class }
)
public class KmsPublicKeyOperations {
    public static void main(String... args) {
        int exitCode = new CommandLine(new KmsPublicKeyOperations()).execute(args);
        System.exit(exitCode);
    }
}
