package uk.gov.di.ipv.kmspublickeyops;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParser;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import uk.gov.di.ipv.service.KmsRsaDecrypter;

import java.text.ParseException;

@Command(name = "jwe-decrypt", description = "decrypt a JWE")
public class JweDecryptCommand implements Runnable {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    @Option(names = "--jwe", required = true, description = "Required: The jwe to decrypt")
    private String jwe;

    @Option(names = "--keyId", required = true, description = "Required: the ID of the KMS key to decrypt with")
    private String keyId;

    @Override
    public void run() {
        KmsRsaDecrypter kmsRsaDecrypter = new KmsRsaDecrypter(keyId);

        JWEObject jarObject;
        try {
            jarObject = JWEObject.parse(jwe);
        } catch (ParseException e) {
            throw new RuntimeException("Unable to parse JWE", e);
        }

        try {
            jarObject.decrypt(kmsRsaDecrypter);
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
