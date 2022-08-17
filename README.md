# KMS Public Key Operations

A tool for doing things with KMS and public keys.

It can 
 - create CSRs and self-signed certificates signed by a private key stored in AWS KMS.
 - create public key JWKs for P-256 EC keys and RSA-2048 keys

## Requirements

You will also need to have AWS credentials for the AWS account the KMS key is located in exported to your environment.
The GDS CLI makes this easy. For example:

```bash
eval $(gds aws di-ipv-dev -e)
```

You will also already need to have a KMS key to work with. More details of what type are in the sections below.

## Usage

### CSRs and Self Signed Certificates

You will need to already have an asymmetric signing key in AWS capable of using RSASSA_PKCS1_V1_5_SHA_256. The key must
have an alias.

#### Creating CSRs

The only two required options are `cn` (common name) and `keyAlias`. You can create a CSR with:

```bash
java -jar jar/di-ipv-kms-public-key-operations-all.jar csr --cn 'My common name' --keyAlias 'alias/myKeyAlias'
```

This will use sensible defaults for the other certificate attributes, but they can be overridden. To see the other
options run:

```bash
java -jar jar/di-ipv-kms-public-key-operations-all.jar csr
```

#### Creating a self-signed certificate

Only three options are required; `cn` (common name), `keyAlias`, and `self-signed`. The value for `self-signed` should be
the number of days the certificate should be valid for.

```bash
java -jar jar/di-ipv-kms-public-key-operations-all.jar csr --cn 'My common name' --keyAlias 'alias/myKeyAlias' --self-signed 365
```

This will use sensible defaults for the other certificate attributes, but they can be overridden. To see the other
options run:

```bash
java -jar jar/di-ipv-kms-public-key-operations-all.jar csr
```

### Public key JWKs

This will only work for KMS keys using the NIST P-256 elliptic curve, or RSA-2048 keys.

The 2 options for this command is the `keyAlias` and `keyUse`. You can create a JWK with:

```bash
java -jar jar/di-ipv-kms-public-key-operations-all.jar jwk --keyAlias 'alias/myKeyAlias' --keyUse 'sig'
```

## Building the jar yourself.

A fat-jar containing all the required dependencies that you can run directly is included in this repo (jar/di-ipv-kms-csr-generator-all.jar).
This is because this tool heavily uses an unpublished library from AWS. The library has been forked to alphagov to allow
us to make changes if required: https://github.com/alphagov/aws-kms-jce

To build the jar you'll need to clone that repo and build it to a local repository (`mvn install -DskipTests`) so it is available as a dependency.

Once you've done that just run:

```bash
./gradlew shadowJar
```

The build jar will be inside the build/libs folder. Just copy the jar ending in "-all" over to the jar folder.