# KMS CSR generator

A tool for creating CSRs signed by a private key stored in AWS KMS.

## Usage

You will need to already have an asymmetric signing key in AWS capable of using RSASSA_PKCS1_V1_5_SHA_256. The key must
have an alias.

You will also need to have AWS credentials for the AWS account the KMS key is located in exported to your environment.
The GDS CLI makes this easy. For example:

```bash
eval $(gds aws di-ipv-dev -e)
```

The only two required options are `cn` (common name) and `keyAlias`. You can create a CSR with:

```bash
java -jar jar/di-ipv-kms-csr-generator-all.jar --cn 'My common name' --keyAlias 'alias/myKeyAlias'
```

This will use sensible defaults for the other certificate attributes but they can be overridden. To see the other
options run:

```bash
java -jar jar/di-ipv-kms-csr-generator-all.jar
```

## Building the jar yourself.

A fat-jar containing all the required dependencies that you can run directly is included in this repo (jar/di-ipv-kms-csr-generator-all.jar).
This is because this tool heavily uses an unpublished library from AWS: https://github.com/aws-samples/aws-kms-jce

To build the jar you'll need to clone that repo and build it to a local repository so it is available as a dependency.

Once you've done that just run:

```bash
./gradlew shadowJar
```
