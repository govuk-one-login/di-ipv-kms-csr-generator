package uk.gov.di.ipv.kmspublickeyops;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParser;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.RSAKey;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import uk.gov.di.ipv.service.KmsRsaDecrypter;

import java.text.ParseException;

@Command(name = "jwe-decrypt", description = "decrypt a JWE")
public class JweDecryptCommand implements Runnable {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    @ArgGroup
    KeySource keySource;

    static class KeySource {
        @Option(names = "--kms-key-id", description = "The ID of the KMS key to decrypt with")
        private String kmsKeyId;

        @Option(names = "--private-key-jwk", description = "The private key JWK to decrypt with")
        private String privateKeyJwk;
    }

    @Option(names = "--jwe", required = true, description = "Required: The jwe to decrypt")
    private String jwe;



    @Override
    public void run() {

        JWEDecrypter decrypter;
        if (keySource.privateKeyJwk != null) {
            try {
                decrypter = new RSADecrypter(
                        RSAKey.parse(keySource.privateKeyJwk));
            } catch (JOSEException | ParseException e) {
                throw new RuntimeException("Unable to parse privateKeyJwk");
            }
        } else {
            decrypter = new KmsRsaDecrypter(keySource.kmsKeyId);
        }

        JWEObject jarObject;
        try {
            jarObject = JWEObject.parse(jwe);
        } catch (ParseException e) {
            throw new RuntimeException("Unable to parse JWE", e);
        }

        try {
            jarObject.decrypt(decrypter);
        } catch (JOSEException e) {
            throw new RuntimeException("Unable to decrypt JWE", e);
        }

        System.out.println("Payload:");
        System.out.println(jarObject.getPayload().toString());

        System.out.println();

        System.out.println("JWT:");
        System.out.println(
                GSON.toJson(
                    JsonParser.parseString(
                            jarObject.getPayload().toSignedJWT().getPayload().toString())));
    }
}
