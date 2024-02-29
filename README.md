# TLS and Certificates Hands-on

- [TLS and Certificates Hands-on](#tls-and-certificates-hands-on)
  - [Your Mission](#your-mission)
    - [Intel/Helpful Resources](#intelhelpful-resources)
  - [Prerequisites](#prerequisites)
  - [TLS (and mutual TLS) Handshake](#tls-and-mutual-tls-handshake)
    - [Background Info](#background-info)
      - [Certificates](#certificates)
      - [Common Types of Certificates](#common-types-of-certificates)
      - [Certificate Hierarchies & Chains](#certificate-hierarchies--chains)
    - [Create Private CA](#create-private-ca)
    - [Create Intermediate Certificate](#create-intermediate-certificate)
    - [Create Server Certificate](#create-server-certificate)
    - [Create Client Certificate](#create-client-certificate)
    - [Test TLS handshake](#test-tls-handshake)
    - [Test mutual TLS Handshake](#test-mutual-tls-handshake)
    - [Explore and Use OS Truststore](#explore-and-use-os-truststore)
  - [TLS (and mutual TLS) with Java](#tls-and-mutual-tls-with-java)
  - [Rotate Certificate](#rotate-certificate)
  - [TLS in Tanzu Application Service](#tls-in-tanzu-application-service)
    - [Non-Java Applications](#non-java-applications)
    - [Java Applications](#java-applications)
    - [Application or Platform Components Access External Endpoint](#application-or-platform-components-access-external-endpoint)
  - [Mutual TLS](#mutual-tls)
    - [Example](#example)
  - [Homework](#homework)
    - [Videos](#videos)
    - [Books](#books)
    - [Projects](#projects)

## Your Mission

Explore and understand the TLS protocol, how certificates are organized, and how they are used in VMware Tanzu products. Steps in this page have been verified on OSX, for Windows we might have to install additional tools. Discuss any additional tools with your facilitator. 

Estimated time: 2-4 hours.


### Intel/Helpful Resources

- [The Illustrated TLS Connection](https://tls.ulfheim.net/)
- [Testing TLS/SSL encryption](https://testssl.sh/)

## Prerequisites

Before you get started, you'll need to make sure you have the following installed:

- Install the `openssl` utility. The one from Brew is newer, so it's preferred.

    ```bash
    brew update
    brew install openssl
    ```

- Install JDK 11. [Preferred](https://bell-sw.com/) but [also acceptable](https://adoptopenjdk.net/).

## TLS (and mutual TLS) Handshake

To get started, we're going to jump in to a full example. This section will cover certificate and key generation, plus steps for running a basic server that we can use to investigate TLS.

### Background Info

#### Certificates

All certificates contain an issuer and a subject. The subject is the person or company that the certificate represents. The issuer is the person that signed the certificate to guarantee it's valid.

#### Common Types of Certificates

1. A self-signed certificate is one where the issuer and the subject are the same. This provides no guarantee to a consumer about the validity of the certificate. It's the subject simply saying "trust me". This is why browsers will display a stern warning before showing a web site protected by a self-signed certificate.

2. A publicly trusted certificate. Most server certificates for public services, like for web servers or email servers, are signed by a public "well known" certificate authority. These authorities sell their services and will sign a certificate for a price. Examples are GeoTrust or Verisign, however there are also free services like Let's Encrypt. When this happens, the issuer is the public certificate authority and the subject is the person paying to have the certificate signed.

    Public certificate authorities are required to confirm a subject's identity before signing the subject's certificate. This is typically done by verifying the subject owns the domain used in the certificate's subject. Common verification methods are requiring a specific DNS TXT record to be set or requiring a specific file to be added to a web server. There is an entire protocol for this called [ACME](https://en.wikipedia.org/wiki/Automated_Certificate_Management_Environment).

3. A corporate certificate. In large corporations, there is often an internal certificate authority for the company. It's not trusted outside of the company, but it's likely trusted on all company computers & servers. Many companies will use this for internal services as a means for reducing costs. In this case, a certificate's issuer would be the company's private CA and the subject would be the service using the certificate.

4. Private certificate authorities. Very similar to a corporate certificate, just on a smaller scale. You can make your own certificate authority and sign as many certificates as you want with it. In this case, the issuer would be your own private CA and the subject would be whatever certificate you'd like to sign. This is useful in labs or in your home office, and it's what we'll use in this document. I hope you'll see it is less work than you might think.

    The main drawback of creating your own private certificate authority is that it won't be trusted by default and that it's your responsibility for ensuring that it's trusted on all your computers. This problem is minimized with DevOps tools like Bosh which can easily deploy a certificate authority to any number of computers.

#### Certificate Hierarchies & Chains

Let's say that you have one certificate, `A`. You can easily create this certificate, deploy it to your server and then share it with anyone that needs to connect. As long as your clients have the server's public certificate, they can connect and establish a trust relationship with the server.

Now let's say you have a second server, which requires another certificate. Then you need a third, and a fourth and a fifth, etc. You could continue on as you're doing, creating certificates and sharing public keys with your clients, but this creates some problems.

First, it's a lot of work. Second, how do you manage all these certs as the number grows? How do you distribute all of these certificates to clients? How do you track when they expire and update them before they expire? What about lost certs or revoking certs? The answer to these questions is basically to use a certificate hierarcy.

Because each certificate has an issuer and a subject, certificates can be organized into hierarchies where one issuer can sign many certificates. In the example below, CA sign certificates A, B, C, D, and E.

```text
         CA
          +
          |
          |
+----+---------+---+
|    |    |    |   |
+    +    +    +   +

A    B    C    D   E
```

The beauty of this organization is that if a user trusts one certificate authority, CA in the example above, the user then trusts all the certificates signed by that authority, A, B, C, D, and E in the example above.

Taking that example further, one user can trust a root (top of the hierarchy) certificate, which may also sign other certificate authorites, which in turn can sign more certificates. All of these certificates will be trusted so long as a user trusts the root certificate authority.

In the example below, trusting ROOT CA would result in automatically trusting CA1-3 and certificates A-O.

```text
                                             ROOT CA
                                                +
                                                |
                                                |
          +--------------------------------------------------------------------------+
          |                                     |                                    |
          |                                     |                                    |
          |                                     |                                    |
          +                                     +                                    +

         CA1                                   CA2                                  CA3

          +                                     +                                    +
          |                                     |                                    |
          |                                     |                                    |
+----+---------+---+                  +----+---------+---+                 +----+---------+---+
|    |    |    |   |                  |    |    |    |   |                 |    |    |    |   |
+    +    +    +   +                  +    +    +    +   +                 +    +    +    +   +

A    B    C    D   E                  F    G    H    I   J                 K    L    M    N   O
```

You may see the term certificate chain mentioned. This is the selection of certificates required to go from the certificate on the server you're accessing back to the root and trusted certificate. In the example above, if you're accessing an email server which presents the certificate `I`, then the certificate chain would be `I` -> `CA2` -> `ROOT CA`.

The way this works is that in order for your browser or email client to trust the server, it must be able to establish trust across the entire certificate chain. From our example, that means it must trust the `ROOT CA`, `CA2` and `I`. A certificate is trusted if it is known to the client directly or if the the certificate is signed by a trusted certificate (i.e. has a trusted issuer).

Looking at our example, to access service `I` we need to trust `ROOT CA`, `CA2` and `I`. If our client knows the `ROOT CA` (it is within it's list of trusted certificates), then we can trust `CA2` because `CA2` is signed by `ROOT CA` and finally, we can trust `I` because it's signed by `CA2`. To present a counter example, if `CA2` was not signed by `ROOT CA` and instead signed by `ROGUE CA`, the validation would fail. We do not trust `ROGUE CA`, so we do not trust `CA2` or `I`.

That's it. We've covered the background material necessary. We're now going to move onto the hands-on labs.

### Create Private CA

The first thing we need is a certificate authority. In this lab, we're going to create a private certificate authority (option #4 from the previous section).

To create the CA, we'll need to create a key and certificate for the CA. Because this is internal, the CA will be self-signed.

To do this:

1. Prepare the directory. Please clone this git repository to your workspace and start from the initial directory.

    ```bash
    git clone https://github.com/Hermen-Nicolau/tls-training
    $ cd tls-training/initial
    ```

2. Create a private key for root CA.

    ```bash
    $ openssl genrsa -out ca.key.pem 2048
    Generating RSA private key, 2048 bit long modulus
    ...........................................................+++
    ...................................................................................................................................+++
    e is 65537 (0x10001)
    ```

3. Create a certificate for the root CA with configuration in `openssl.cnf` and validity as 1460 days (4 years).

    Often a production private CA certificate will have a much longer life time. This is because a.) it's difficult to distribute private CAs to clients and b.) if the CA cert expires, so do all the certs signed by it.

    **Before you run the command below**, please edit `openssl_ca.cnf` and replace value of `dir` (just once at the top) to definite path of `ca` directory. The `openssl` commands require a full path.

    ```bash
    $ openssl req -config openssl_ca.cnf -new -x509 -days 1460 -sha256 -extensions v3_ca -key ca.key.pem -out ca.cert.pem
    You are about to be asked to enter information that will be incorporated
    into your certificate request.
    What you are about to enter is what is called a Distinguished Name or a DN.
    There are quite a few fields but you can leave some blank
    For some fields there will be a default value,
    If you enter '.', the field will be left blank.
    -----
    Country Name (2 letter code) []:
    State or Province Name []:
    Locality Name []:
    Organization Name [Merck]:
    Organizational Unit Name [ADP]:
    Common Name []:myCA
    Email Address []:
    ```

    For more details about Distinguished Name, please refer to article - [What is a Distinguished Name?](https://knowledge.digicert.com/generalinformation/INFO1745)

4. View the certificate. Check out the Issuer, Validity and Subject. Confirm the information you entered. As it's the private root CA, subject is as same as issuer.

    ```bash
    $ openssl x509 -in ca.cert.pem -noout -text
    Certificate:
        Data:
            Version: 3 (0x2)
            Serial Number: 9476611219168289694 (0x8383afb1d101e39e)
        Signature Algorithm: sha256WithRSAEncryption
            Issuer: O=VMware, OU=MAPBU Support, CN=myRootCA
            Validity
                Not Before: Jun 21 09:46:11 2020 GMT
                Not After : Jun 20 09:46:11 2024 GMT
            Subject: O=VMware, OU=MAPBU Support, CN=myRootCA
            ...
            X509v3 extensions:
                X509v3 Subject Key Identifier:
                    F3:43:AB:27:D2:BC:26:4C:F4:F7:00:D2:F2:42:80:A3:10:5E:B1:ED
                X509v3 Authority Key Identifier:
                    keyid:F3:43:AB:27:D2:BC:26:4C:F4:F7:00:D2:F2:42:80:A3:10:5E:B1:ED

                X509v3 Basic Constraints: critical
                    CA:TRUE
                X509v3 Key Usage: critical
                    Digital Signature, Certificate Sign, CRL Sign
    ```

You're now all set and have a private certificate authority, which you can use to sign other certificates.

### Create Intermediate Certificate

Leaf certificates can be signed by a root CA directly, but we want to introduce intermediate CAs and explain how trust chain works (intermediate certificates are useful for other reasons as well, like mitigating the risk of a CA being compromised and making rotations easier). In this section, you'll create an intermediate CA and signs it with the root CA. The steps are similar to [Create Private CA](#create-private-ca) but with some different configurations.

1. Create an intermediate CA with 730 days (2 years) validity.

    ```bash
    $ openssl genrsa -out intermediate.key.pem 2048
    Generating RSA private key, 2048 bit long modulus
    ...........................................................+++
    ...................................................................................................................................+++
    e is 65537 (0x10001)
    ```

2. Create a intermediate CA certificate signing request(CSR)

    ```bash
    $ openssl req -config openssl_intermediate.cnf -new -sha256 \
        -key intermediate.key.pem \
        -out intermediate.csr
    -----
    You are about to be asked to enter information that will be incorporated
    into your certificate request.
    What you are about to enter is what is called a Distinguished Name or a DN.
    There are quite a few fields but you can leave some blank
    For some fields there will be a default value,
    If you enter '.', the field will be left blank.
    -----
    Country Name (2 letter code) []:
    State or Province Name (full name) []:
    Locality Name (eg, city) []:
    Organization Name (eg, company) []:Merck
    Organization Unit Name (eg, section) []:ADP
    Common Name (e.g. server FQDN or YOUR name) []:myIntermediateCA
    Email Address []:
    ```

3. Sign the intermediate CSR with root CA, set validatiy as 730 days, use `v3_intermediate_ca` X509 extension in `openssl_ca.cnf`. See that section in the file for the specific configuration being used.

    ```bash
    $ openssl ca -config openssl_ca.cnf -cert ca.cert.pem -keyfile ca.key.pem -days 730 \
        -extensions v3_intermediate_ca -notext -outdir . \
        -in intermediate.csr -out intermediate.cert.pem
    Using configuration from openssl_ca.cnf
    Check that the request matches the signature
    Signature ok
    Certificate Details:
            Serial Number: 4096 (0x1000)
            Validity
                Not Before: Jun 21 09:53:07 2020 GMT
                Not After : Jun 21 09:53:07 2022 GMT
            Subject:
                organizationName          = Merck
                organizationalUnitName    = ADP
                commonName                = myIntermediateCA
            X509v3 extensions:
                X509v3 Subject Key Identifier:
                    B7:8F:0B:64:00:F4:84:90:C8:5B:DC:ED:53:E0:7F:5F:F2:00:8E:96
                X509v3 Authority Key Identifier:
                    keyid:F3:43:AB:27:D2:BC:26:4C:F4:F7:00:D2:F2:42:80:A3:10:5E:B1:ED

                X509v3 Basic Constraints: critical
                    CA:TRUE, pathlen:0
                X509v3 Key Usage: critical
                    Digital Signature, Certificate Sign, CRL Sign
    Certificate is to be certified until Jun 21 09:53:07 2022 GMT (730 days)
    Sign the certificate? [y/n]:y


    1 out of 1 certificate requests certified, commit? [y/n]y
    Write out database with 1 new entries
    Data Base Updated
    ```

4. View the certificate. Check out the Issuer, Validity and Subject.

    ```bash
    $ openssl x509 -in intermediate.cert.pem -noout -text
    Certificate:
        Data:
            Version: 3 (0x2)
            Serial Number: 4096 (0x1000)
        Signature Algorithm: sha256WithRSAEncryption
            Issuer: O=VMware, OU=MAPBU Support, CN=myRootCA
            Validity
                Not Before: Jun 21 09:53:07 2020 GMT
                Not After : Jun 21 09:53:07 2022 GMT
            Subject: O=VMware, OU=MAPBU Support, CN=myIntermediateCA
            Subject Public Key Info:
            ...
            X509v3 extensions:
                X509v3 Subject Key Identifier:
                    B7:8F:0B:64:00:F4:84:90:C8:5B:DC:ED:53:E0:7F:5F:F2:00:8E:96
                X509v3 Authority Key Identifier:
                    keyid:F3:43:AB:27:D2:BC:26:4C:F4:F7:00:D2:F2:42:80:A3:10:5E:B1:ED
                X509v3 Basic Constraints: critical
                    CA:TRUE, pathlen:0
                X509v3 Key Usage: critical
                    Digital Signature, Certificate Sign, CRL Sign
    ```

You're now all set and have a intermediate certificate authority, which you can use to sign leaf certificates.

### Create Server Certificate

With your private root CA and intermediate CA in hand, you can now create & sign any number of certificates which you can use to secure your servers.

1. Create an `openssl` config file called `server_req.conf`. This is required to add a SAN (Subject Alternative Name) to our certificate.

   A SAN can be the value of an E-mail address, IP addresses, FQDNs, wildcard domains(\*.DOMAIN) and other names. TLS certificate validation verifies hostname match, so we need to create the server certificate with SAN match its FQDN, IP address or wildcard domain. In this test, we'll use IP address to skip any DNS configuration.

    ```bash
    $ cat << EOF > server_req.cnf
    [ req ]
    default_bits        = 2048
    distinguished_name  = req_distinguished_name
    req_extensions      = v3_req

    [ req_distinguished_name ]
    countryName                     = Country Name (2 letter code)
    stateOrProvinceName             = State or Province Name
    localityName                    = Locality Name
    organizationName                = Organization Name
    organizationalUnitName          = Organizational Unit Name
    commonName                      = Common Name (e.g. server FQDN or YOUR name)

    # Optionally, specify some defaults.
    organizationName_default        = Merck
    organizationalUnitName_default  = ADP
    commonName_default              = localhost

    [ v3_req ]
    basicConstraints = CA:FALSE
    subjectAltName = @alt_names

    [ alt_names ]
    IP.1 = 127.0.0.1
    EOF
    ```

2. Create a server key and CSR with:

    - 365 days validity
    - Common Name as localhost
    - a SAN of `IP:127.0.0.1`

    ```bash
    $ openssl genrsa -out server.key.pem 2048
    Generating RSA private key, 2048 bit long modulus
    ................+++
    ..........+++
    e is 65537 (0x10001)

    $ openssl req -new -config server_req.cnf -days 365 -key server.key.pem -out server.csr
    You are about to be asked to enter information that will be incorporated
    into your certificate request.
    What you are about to enter is what is called a Distinguished Name or a DN.
    There are quite a few fields but you can leave some blank
    For some fields there will be a default value,
    If you enter '.', the field will be left blank.
    -----
    Country Name (2 letter code) []:
    State or Province Name []:
    Locality Name []:
    Organization Name [Merck]:
    Organizational Unit Name [ADP]:
    Common Name (e.g. server FQDN or YOUR name) [localhost]:
    ```

3. Sign the certificate with your intermediate CA.

    ```bash
    $ openssl ca -config openssl_intermediate.cnf -extensions server_cert -days 365 -notext -md sha256 \
        -keyfile intermediate.key.pem -cert intermediate.cert.pem \
        -in server.csr -outdir . -out server.cert.pem
    ```

    You should now have a certificate and a key, signed by the your private certificate authority.

    Check it out. Run the following command and look at the Issuer, Subject and X509v3 Subject Alternative Name towards the bottom.

    ```bash
    $ openssl x509 -in server.cert.pem -noout -text
    Certificate:
        Data:
            Version: 3 (0x2)
            Serial Number: 4101 (0x1005)
        Signature Algorithm: sha256WithRSAEncryption
            Issuer: O=VMware, OU=MAPBU Support, CN=myIntermediateCA
            Validity
                Not Before: Jun 21 14:52:37 2020 GMT
                Not After : Jun 21 14:52:37 2021 GMT
            Subject: O=VMware, OU=MAPBU Support, CN=localhost
            Subject Public Key Info:
            ...
            X509v3 extensions:
                X509v3 Basic Constraints:
                    CA:FALSE
                Netscape Cert Type:
                    SSL Server
                Netscape Comment:
                    OpenSSL Generated Server Certificate
                X509v3 Subject Key Identifier:
                    9A:A4:CF:7E:3F:3C:A6:14:91:84:01:E2:EC:04:F0:C5:94:C2:13:CA
                X509v3 Authority Key Identifier:
                    keyid:B7:8F:0B:64:00:F4:84:90:C8:5B:DC:ED:53:E0:7F:5F:F2:00:8E:96
                    DirName:/O=VMware/OU=MAPBU Support/CN=myRootCA
                    serial:10:00

                X509v3 Key Usage: critical
                    Digital Signature, Key Encipherment
                X509v3 Extended Key Usage:
                    TLS Web Server Authentication
                X509v3 Subject Alternative Name:
                    IP Address:127.0.0.1
    ```

4. Check if certificate / key is a valid pair.

    Certificate and key must match otherwise they can't decode encrypted messages by peer. As both should contain same public key, you can extract public key and confirm they are identical.  

    ```bash
    $ openssl x509 -in server.cert.pem -pubkey -noout
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAseB99POPv1mcZhGa0rPy
    iIknTaGWYY+SI/zCcJtF8t3XKet0kc200bqB0HT6gtq/07Fp9WQj3yFhWp+W68ru
    fGbpoUFzjnM7H/4cp4RGe1qr3de1qkvoUPJHTpqKnuA8fCtR2TaqGgvRoC32jS3P
    8FS0+a5awtE60rTdwGq39PKW5T9fkBmXjHZKrNFIXwhIAiTDqcv+kgFiOmySSDuh
    3jUC+0n/iQksbZXsi6xP+eNtUvGc51i5kJxuCEc9be4vyPQ6Ownh/U9HQWiQxKrA
    Dx4GmdRMQVEhekJuQFs0mrm5ur0ukpMTlt2bt2P+TJq9glpgjvL95AtEKz3vX3Ud
    ZwIDAQAB
    -----END PUBLIC KEY-----
    $ openssl pkey -in server.key.pem -pubout
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAseB99POPv1mcZhGa0rPy
    iIknTaGWYY+SI/zCcJtF8t3XKet0kc200bqB0HT6gtq/07Fp9WQj3yFhWp+W68ru
    fGbpoUFzjnM7H/4cp4RGe1qr3de1qkvoUPJHTpqKnuA8fCtR2TaqGgvRoC32jS3P
    8FS0+a5awtE60rTdwGq39PKW5T9fkBmXjHZKrNFIXwhIAiTDqcv+kgFiOmySSDuh
    3jUC+0n/iQksbZXsi6xP+eNtUvGc51i5kJxuCEc9be4vyPQ6Ownh/U9HQWiQxKrA
    Dx4GmdRMQVEhekJuQFs0mrm5ur0ukpMTlt2bt2P+TJq9glpgjvL95AtEKz3vX3Ud
    ZwIDAQAB
    -----END PUBLIC KEY-----
    ```

### Create Client Certificate

Similar to the previous section, here you will create a client certificate/key pair that will be used for mutual TLS. The general process is the same. Create a key, create a CSR and sign the request using your private certificate authority.

1. Create a client key and CSR with:

    ```bash
    $ openssl genrsa -out client.key.pem 2048
    Generating RSA private key, 2048 bit long modulus
    ............................................+++
    ..+++
    e is 65537 (0x10001)

    $ openssl req -new -days 365 -key client.key.pem -out client.csr
    You are about to be asked to enter information that will be incorporated
    into your certificate request.
    What you are about to enter is what is called a Distinguished Name or a DN.
    There are quite a few fields but you can leave some blank
    For some fields there will be a default value,
    If you enter '.', the field will be left blank.
    -----
    Country Name (2 letter code) []:
    State or Province Name (full name) []:
    Locality Name (eg, city) []:
    Organization Name (eg, company) []:VMware
    Organizational Unit Name (eg, section) []:MAPBU Support
    Common Name (eg, fully qualified host name) []:myClientCert
    Email Address []:

    Please enter the following 'extra' attributes
    to be sent with your certificate request
    A challenge password []:
    ```

2. Sign the client certificate with intermediate CA.

    In this case, we're signing it with the same intermediate CA that is used on the server, but that does not need to be the case. You can have the client signed by any certificate authority that is trusted by the server.

    ```bash
    $ openssl ca -config openssl_intermediate.cnf -extensions client_cert -days 365 -notext -md sha256 \
        -keyfile intermediate.key.pem -cert intermediate.cert.pem \
        -in client.csr -outdir . -out client.cert.pem
    ```

3. You can take a peek at your client certificate. Again, note the issuer & subject.

    ```bash
    $ openssl x509 -in client.cert.pem -noout -text
    Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 4100 (0x1004)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: O=VMware, OU=MAPBU Support, CN=myIntermediateCA
        Validity
            Not Before: Jun 21 10:52:28 2020 GMT
            Not After : Jun 21 10:52:28 2021 GMT
        Subject: O=VMware, OU=MAPBU Support, CN=myClientCert
        Subject Public Key Info:
        ...
        X509v3 extensions:
            X509v3 Basic Constraints:
                CA:FALSE
            Netscape Cert Type:
                SSL Client, S/MIME
            Netscape Comment:
                OpenSSL Generated Client Certificate
            X509v3 Subject Key Identifier:
                E1:90:40:78:A1:4F:3F:A2:40:B2:C7:2F:CA:8F:07:70:CA:77:70:12
            X509v3 Authority Key Identifier:
                keyid:B7:8F:0B:64:00:F4:84:90:C8:5B:DC:ED:53:E0:7F:5F:F2:00:8E:96
            X509v3 Key Usage: critical
                Digital Signature, Non Repudiation, Key Encipherment
            X509v3 Extended Key Usage:
                TLS Web Client Authentication, E-mail Protection
    ```

### Test TLS handshake

At this point, all of the set up has been finshed. We've got enough certificates generated to have some fun. We're now going to step through what a TLS handshake looks like between a client and a server.

1. Start a server with the server certificate/key. We'll be using `openssl s_server` which creates a generic TCP server, similar to `nc -l` but that is secured with TLS.

    - `-www` flag tells our test server to respond to an HTTP request for 'GET /' with a status page
    - `-state` prints the SSL states of each handshake step, this lets us inspect what is happening when the client connects
    - `-CAfile` includes the intermediate CA. It is the responsibility of the server to include all intermediate CA certificates, for a client to validate the certificate chain.

    ```bash
    $ openssl s_server -cert server.cert.pem -key server.key.pem -CAfile intermediate.cert.pem -accept 4443 -www -state
    Using auto DH parameters
    Using default temp ECDH parameters
    ACCEPT
    ```

2. Now we're going to send some requests to the server with `curl`.

    a. Access the server over HTTPS without CA certificte. Note how validation fails. This is because our private certificate authority is not trusted by `curl` out-of-the-box. By default, `curl` read CAs from system truststore, as the CA we created is not imported into OS truststore, the verifiation can't pass.

    ```bash
    $ curl https://localhost:4443
    curl: (60) SSL certificate problem: unable to get local issuer certificate
    ...
    ```

    b. In order to trust server certificate, `curl` should provide the certificate chain(both the private root CA and intermediate CA). Access the server over HTTPS with trust chain. This still fails, but now it's because the hostname doesn't match the one that was entered in the server certificate as the common name or a SAN.

    ```bash
    $ curl https://localhost:4443 --cacert ca.cert.pem
    curl: (51) SSL: no alternative certificate subject name matches target host name 'localhost'
    ```

    c. Access the server over HTTPS with CA certificte and a hostname that matches the server certificate CN. You should get a successful response, yay!

    ```bash
    $ curl https://127.0.0.1:4443 --cacert ca.cert.pem
    <HTML><BODY BGCOLOR="#ffffff">
    ...
    ---
    New, TLSv1/SSLv3, Cipher is ECDHE-RSA-AES256-GCM-SHA384
    SSL-Session:
        Protocol  : TLSv1.2
        Cipher    : ECDHE-RSA-AES256-GCM-SHA384
        Session-ID: FC0963891702F03F2147AE3B532381A0EE0570F51ECD88E680EE644C2503413D
        Session-ID-ctx: 01000000
        Master-Key: 8C1FBF34620A573D18C06D88E908EB9D8F57FACECC46D12920EEE5C3186D677E1A6F2B0E3B3EF6BA3C3AB9D5952A153F
        Start Time: 1592491277
        Timeout   : 7200 (sec)
        Verify return code: 0 (ok)
    ---
    2 items in the session cache
    0 client connects (SSL_connect())
    0 client renegotiates (SSL_connect())
    0 client connects that finished
    5 server accepts (SSL_accept())
    0 server renegotiates (SSL_accept())
    2 server accepts that finished
    0 session cache hits
    0 session cache misses
    0 session cache timeouts
    0 callback cache hits
    0 cache full overflows (128 allowed)
    ---
    no client certificate available
    </BODY></HTML>
    ```

3. The test can also be executed with `openssl` utility

    a. Connect to server with `openssl s_client` instead of `curl`.

    ```bash
    $ openssl s_client -connect 127.0.0.1:4443 -CAfile ca.cert.pem
    CONNECTED(00000003)
    depth=2 O = VMware, OU = MAPBU Support, CN = myRootCA
    verify return:1
    depth=1 O = VMware, OU = MAPBU Support, CN = myIntermediateCA
    verify return:1
    depth=0 O = VMware, OU = MAPBU Support, CN = localhost
    verify return:1
    ---
    Certificate chain
    0 s:/O=VMware/OU=MAPBU Support/CN=localhost
    i:/O=VMware/OU=MAPBU Support/CN=myIntermediateCA
    ...
        Verify return code: 0 (ok)
    ---
    ```

    b. Please review server side logs printed out by `openssl` how the handshake works, if you want to check further details, please appened `-debug` option with `openssl` which dump handshake traffic. In addition, you can step through the client/server logs and compare to the [Illustrated TCP Guide](https://tls.ulfheim.net/). Lastly, `openssl s_client` with `-showcerts` can display the server cert downloaded from server.

    ```bash
    # view the server cert
    $ openssl s_client -showcerts -connect 127.0.0.1:4443 < /dev/null |  sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p'
    ...
    ```

### Test mutual TLS Handshake

We're now going to step through what a mutual TLS handshake looks like between a client and a server. As it's named, in mutual TLS handshake, client side should provide certificate for server to verify.

1. Start server with the server certificate/key as above, with  `-verify 3` or `-Verify 3` appened.

    - the number 3 is the verification depth (Root CA signs intermediate CA, intermediate signs lower layer intermediate CA or leaf certificates, which makes up a chain with depth).
    - `verify`turns on peer certificate verification, client has the option to provide a cert.
    - `Verify`turns on peer certificate verification, client must provide a cert (note this is the option with a capital "V").

    ```bash
    $ openssl s_server -cert server.cert.pem -key server.key.pem -CAfile intermediate.cert.pem -accept 4443 -www -state -verify 3

    # this works without client cert because -verify request but doesn't require client certificate.
    $ curl https://127.0.0.1:4443 --cacert ca.cert.pem
    ...
    no client certificate available
    ...
    # if client provides client cert and key, server will verify it
    $ curl https://127.0.0.1:4443 --cacert ca.cert.pem --cert client.cert.pem --key client.key.pem
    ...
    ```

    The handshake steps printed by `openssl s_server` indicates it receives client cert and verify it.

    ```text
    SSL_accept:before/accept initialization
    SSL_accept:SSLv3 read client hello A
    SSL_accept:SSLv3 write server hello A
    SSL_accept:SSLv3 write certificate A
    SSL_accept:SSLv3 write key exchange A
    SSL_accept:SSLv3 write certificate request A
    SSL_accept:SSLv3 write server done A
    SSL_accept:SSLv3 flush data
    depth=2 O = VMware, OU = MAPBU Support, CN = myRootCA
    verify error:num=19:self signed certificate in certificate chain
    verify return:1
    depth=2 O = VMware, OU = MAPBU Support, CN = myRootCA
    verify return:1
    depth=1 O = VMware, OU = MAPBU Support, CN = myIntermediateCA
    verify return:1
    depth=0 O = VMware, OU = MAPBU Support, CN = myClientCert
    verify return:1
    SSL_accept:SSLv3 read client certificate A
    SSL_accept:SSLv3 read client key exchange A
    SSL_accept:SSLv3 read certificate verify A
    SSL_accept:SSLv3 read finished A
    SSL_accept:SSLv3 write change cipher spec A
    SSL_accept:SSLv3 write finished A
    SSL_accept:SSLv3 flush data
    ACCEPT
    ```

2. Stop server and start with `-Verify 3` option, in this case, client must provide client certificate.

    ```bash
    $ openssl s_server -cert server.cert.pem -key server.key.pem -CAfile intermediate.cert.pem -accept 4443 -www -state -Verify 3

    $ curl https://127.0.0.1:4443 --cacert ca.cert.pem
    curl: (35) error:1401E410:SSL routines:CONNECT_CR_FINISHED:sslv3 alert handshake failure
    $ curl https://127.0.0.1:4443 --cacert ca.cert.pem --cert client.cert.pem --key client.key.pem
    # succeeds here
    ```

### Explore and Use OS Truststore

1. For certificates signed by public CA (or chain)

    Because root CA is trusted by OS, the intermiedate CA or leaf certificate signed by the public CA will be trusted. For example when access `https://example.com`.

    ```bash
    $ curl -v -I  https://example.com
    ...
    *  SSL certificate verify ok.
    ...

    $ openssl s_client -connect example.com:443 -state
    CONNECTED(00000005)
    SSL_connect:before/connect initialization
    SSL_connect:SSLv3 write client hello A
    SSL_connect:SSLv3 read server hello A
    depth=2 C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert Global Root CA
    verify return:1
    depth=1 C = US, O = DigiCert Inc, CN = DigiCert SHA2 Secure Server CA
    verify return:1
    depth=0 C = US, ST = California, L = Los Angeles, O = Internet Corporation for Assigned Names and Numbers, OU = Technology, CN = www.example.org
    verify return:1
    SSL_connect:SSLv3 read server certificate A
    SSL_connect:SSLv3 read server key exchange A
    SSL_connect:SSLv3 read server done A
    SSL_connect:SSLv3 write client key exchange A
    SSL_connect:SSLv3 write change cipher spec A
    SSL_connect:SSLv3 write finished A
    SSL_connect:SSLv3 flush data
    SSL_connect:SSLv3 read server session ticket A
    SSL_connect:SSLv3 read finished A
    ---
    Certificate chain
    0 s:/C=US/ST=California/L=Los Angeles/O=Internet Corporation for Assigned Names and Numbers/OU=Technology/CN=www.example.org
    i:/C=US/O=DigiCert Inc/CN=DigiCert SHA2 Secure Server CA
    1 s:/C=US/O=DigiCert Inc/CN=DigiCert SHA2 Secure Server CA
    i:/C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Global Root CA
    2 s:/C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Global Root CA
    i:/C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Global Root CA
    ...
        Verify return code: 0 (ok)
    ---
    ```

    - Root CA `DigiCert Global Root CA` signs intermediate CA `DigiCert SHA2 Secure Server CA`
    - Intermediate CA `DigiCert SHA2 Secure Server CA` signs the server certificate used by `https://example.com`.
    - When issuing `curl` or `openssl`, the client utility downloads the certificate chain from server, because the public root CA is available in OS truststore, the chain(intermediate CA and leaf certificate) can be verified and trusted.

    ```bash
    $ grep "DigiCert Global Root CA" /etc/ssl/cert.pem
    === /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Global Root CA
            Subject: C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root CA
    ```

    You may refer to article - [How certificate chains work](https://knowledge.digicert.com/solution/SO16297.html).

2. For certificates signed by private CA

    - The root CA certificate should be specified when accessing server.
    - Or the root CA should be imported into OS truststore, then apps or utilities(curl, openssl) can read it from OS truststore.
        - For OSX, the private CA can be added with `keychain Access` utility.
        - For Ubuntu, copy the CA or chain into /etc/ssl/certs, followed by `sudo update-ca-certificates -f -v`.

    Once the private CA is added to OS truststore, it won't be necessary to specifify the `-CAfile` argument.

## TLS (and mutual TLS) with Java

Instead of using the OS truststore (i.e. `/etc/ssl/certs` on Ubuntu), Java manages its own list of trusted certificates.

There are two types:

- **trustStore**: stores the public keys for trusted Certificate authorities(CA) which is used for verifying certificates presented by a server
- **keystore**: stores private keys which are often used as identity certificates (i.e. client certificate for mutual TLS)

In Java, the file itself is also called a "keystore". The default file format is "Java Keystore" or JKS. The keystore file in this format, can be functionally used as a keystore (to store keys), as a truststore (to store trusted public certs) or as both. The specific usage depends on the application that is using the file.

1. Test a Java app without a truststore.

    The code for this test comes from the [Java example here](https://docs.oracle.com/javase/10/security/sample-code-illustrating-secure-socket-connection-client-and-server.htm).

    Please append the server IP (local IP in this case) and port arguments when you run the SSLSocketClient.

    1. Start the server.

        ```bash
        openssl s_server -cert server.cert.pem -key server.key.pem -CAfile intermediate.cert.pem -accept 4443 -www -state
        ```

    2. Compile and run the Java client app (code provided und), which connects to the server from step #1.

        ```bash
        $ cd ../java
        $ javac SSLSocketClient.java
        $ java SSLSocketClient 127.0.0.1 4443
        javax.net.ssl.SSLHandshakeException: sun.security.validator.ValidatorException: PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target
        ...
        ```

    It fails as expected because the Java app can't verify server certificate.

2. Create a truststore.

    The following commands creates a new truststore file `myTrustStore` and import the root CA created in previous steps. Please give a password and type `yes` to trust the certificates.

    ```bash
    $  keytool -import -file ../initial/ca.cert.pem -alias myRootCA -keystore myTrustStore.jks
    Enter keystore password:
    Re-enter new password:
    Owner: CN=myRootCA, OU=MAPBU Support, O=VMware
    Issuer: CN=myRootCA, OU=MAPBU Support, O=VMware
    Serial number: 8383afb1d101e39e
    ...
    Trust this certificate? [no]:  yes
    Certificate was added to keystore
    ```

    Now run this command to view the contents of your truststore.

    ```bash
    $ keytool -list -keystore myTrustStore.jks
    Enter keystore password:
    Keystore type: PKCS12
    Keystore provider: SUN

    Your keystore contains 1 entry

    myrootca, Jun 26, 2020, trustedCertEntry,
    Certificate fingerprint (SHA-256): 09:19:C2:9F:49:79:14:D6:23:26:4F:F7:FB:60:AF:FF:81:0D:E9:BE:36:AE:5C:07:7D:00:B7:72:49:F6:F4:C1
    ```

3. Test the Java app with truststore

    ```bash
    $ java -Djavax.net.ssl.trustStore=myTrustStore.jks -Djavax.net.ssl.trustStorePassword="your-password" SSLSocketClient 127.0.0.1 4443
    HTTP/1.0 200 ok
    Content-type: text/html
    ...
    no client certificate available
    </BODY></HTML>
    ```

    It works! The truststore contains `myRootCA` and now the Java app can verify the certificate presented by the server and establish a chain of trust.

4. Test mutual TLS with Java

    Enable mutual TLS on server side with option `-Verify 3`, the client app now MUST provide a client cert.

    ```bash
    openssl s_server -cert server.cert.pem -key server.key.pem -CAfile intermediate.cert.pem -accept 4443 -www -state -Verify 3
    ```

    Now run this command.

    ```bash
    $ java -Djavax.net.ssl.trustStore=myTrustStore.jks -Djavax.net.ssl.trustStorePassword="your-password" SSLSocketClient 127.0.0.1 4443
    127.0.0.1
    4443
    javax.net.ssl.SSLHandshakeException: Received fatal alert: handshake_failure
        at sun.security.ssl.Alerts.getSSLException(Alerts.java:192)
    ```

    The Java app fails to complete a TLS handshake. Note how the openssl server complains `peer did not return a certifidate`, which means a certificate was not provided.

    ```text
    SSL3 alert write:fatal:handshake failure
    SSL_accept:error in SSLv3 read client certificate B
    4578821740:error:140360C7:SSL routines:ACCEPT_SR_CERT:peer did not return a certificate:/BuildRoot/Library/Caches/com.apple.xbs/Sources/libressl/libressl-22.260.1/libressl-2.6/ssl/ssl_srvr.c:2419:
    ```

    To make it work, create a keystore for the Java app. Keytool can't import private key into a keystore(.jks) directly, client cert/key should be converted into PKCS 12 (.p12) file first.

    1. Input the export password when being prompted, for example, use "password".

        ```bash
        $ openssl pkcs12 -export -in client.cert.pem -inkey client.key.pem \
        -name myClient  -out myClient.p12
        Enter Export Password:
        Verifying - Enter Export Password:
        ```

    2. Now use `keytool` to convert from PKCS12 format to a Java keystore file. **Side note** this is optional. The JVM understands PKCS12 formatted keystores, you just need to set the format with `-Djavax.net.ssl.keyStoreType=pkcs12`. We're going to convert it though in this example.

        ```bash
        $ keytool -importkeystore -srckeystore myClient.p12 -srcstorepass changeit -srcstoretype pkcs12 -destkeystore myClient.jks -deststorepass your-password
        Importing keystore myClient.p12 to myClient.jks...
        Entry for alias myclient successfully imported.
        Import command completed:  1 entries successfully imported, 0 entries failed or cancelled
        ```

    Confirm the Java app completes mutual TLS successfully with server by providing keystore.

    ```bash
    $ java -Djavax.net.ssl.trustStore=myTrustStore.jks -Djavax.net.ssl.trustStorePassword="your-password" -Djavax.net.ssl.keyStore=myClient.jks -Djavax.net.ssl.keyStorePassword="your-password" SSLSocketClient 127.0.0.1 4443

    HTTP/1.0 200 ok
    ...
    ```

## Rotate Certificate

1. Rotate Leaf Certificate

    This is single-step operation. When the root CA (or an intermediate CA) is unchanged, simply replace leaf certificates with new ones. Because the new leaf certificates are signed by same CA, its peer can still verify them.

2. Rotate Root CA

    This should be seperated into 3 steps.

    1. Create the new CA and add the CA file to the OS/Java truststore, both old and new CAs coexist.

    2. Regenerate all leaf certs with certs signed by the new CA and deploy. Because clients trust both CAs, a client can verify leaf certs signed by either of them.

    3. When all clients and services have been upgraded with certificates signed by the new root CA, then you can remove the old root CA. This is optional though as the old root CA will expire and no longer be valid anyway.

3. Rotate Intermediate CA

    The process for rotating an intermediate CA is the same as that of a root CA, the number of impacted certs is just less.

    For step #2, regenerating leaf certificates. You would only need to regenerate leaf certificates signed by the intermediate CA, instead of all leaf certs under the root CA. This is an advantage of using intermediate CAs, you can lower the number of certificates that need to be changed when an intermediate CA expires.

## TLS in Tanzu Application Service

### Non-Java Applications

Some system apps on TAS access the platform API (api.SYS_DOMAIN), UAA(uaa.SYS_DOMAIN) or other endpoints. These are protected by the certificates deployed to the foundation. Those certificates may be signed by a public CA, an internal CA or they may be self-signed.

If they are signed by an internal CA or if they are self-signed, then the certificate needs to be added to Bosh's list of trusted certificates.

Most corporations use internal CA and the trust chain looks like this.

```bash
$ openssl s_client -connect api.<your domain>:443 | grep "Certificate chain" -A 5
...
Certificate chain
0 s:/C=US/ST=California/L=San Francisco/O=Pivotal Inc/OU=Support/CN=*.<your domain>
i:/C=US/ST=California/O=Pivotal Inc/OU=Support/CN=Pivotal Support Lab #06
1 s:/C=US/ST=California/O=Pivotal Inc/OU=Support/CN=Pivotal Support Lab #06
i:/C=US/ST=California/L=San Francisco/O=Pivotal Inc/OU=Support/CN=Pivotal Support Labs Root CA/emailAddress=gss-labs@pivotal.io
```

- Root CA: `Pivotal Support Labs Root CA`
- Intermediate CA: `Pivotal Support Lab #06`
- Leaf Certificate: `*.<your domain>`

`Pivotal Support Labs Root CA` is not public CA, so in order to trust the CA the root CA should be added to `Ops Manager > Director > Settings > Security > Trusted Certificates`. BOSH and Garden will take care of deploying the root CA and any other Bosh trusted certs into every VM and container's default certificate bundle (i.e.`/etc/ssl/certs/ca-certificates.crt`). Note that for your laptop to trust our labs, you must add the Pivotal Support Labs Root CA to the trust store (KeyChain on Mac) of your laptop.

With certificates trusted everywhere that enables services running on VMs and applications running on containers in the foundation to talk to the API or UAA or other services without encountering any certificate trust issues and without needing to check the box to ignore SSL errors (which should never be checked in production, as it defeats the purpose of TLS).

### Java Applications

The one exception to the previous section is for Java applications. As we previously discussed, Java maintains its own truststore, so it won't use the system provided truststore which Bosh & Garden populate.

For Java apps running as Bosh deployed jobs, making this work is on the job's author. Most jobs in TAS & service tiles include code to read the OS truststore and add those certificates into the JVM's default truststore. This is worth noting because the process occasionally breaks and we have to debug it.

For Java apps running as applications on CF, the Java buildpack loads OS's trusted CAs from `/etc/ssl/certs/ca-certificates.crt` into Java's default truststore. Please refer to [java-buildpack-security-provider](https://github.com/cloudfoundry/java-buildpack-security-provider/blob/main/src/main/java/org/cloudfoundry/security/CloudFoundryContainerTrustManagerFactory.java) for details.

### Application or Platform Components Access External Endpoint

Some system apps on TAS access external endpoints, such as blobstore, IaaS API endpoint, external data services over TLS. If those certificates are signed by internal CA or they are self-signed., the trusted should be configured at `Ops Manager > Director > Settings > Security > Trusted Certificates` by including the internal CA certificates or the self-signed certificates.

## Mutual TLS

A nice feature of CF is that every container is provided an instance identification cert/key under `/etc/cf-instance-credentials/`. This key can be used to identify the application to other resources, such as other apps on the foundation or even CredHub.

Any application can make use of this certificate, but the Java buildpack makes this even easier because it will enable Java app to send out the container instance id client/key when a TLS connection is created by default.

In some cases, this default behavior causes problems. For example, if the remote server doesn't trust the instance id cert so this behavior can be disabled. Please refer to [details](https://github.com/cloudfoundry/java-buildpack/blob/main/docs/framework-container_security_provider.md). This default behavior does not prohibit a Java developer from performing mutual TLS with their own key either. It is simply the default, which you can override if necessary.

### Example

1. The `rep` on Diego Cells connects to BBS over mutual TLS(client cert/key pair is required).

    - config: /var/vcap/jobs/rep/config
    - cert/key: /var/vcap/jobs/rep/config/certs

    ```bash
    $ curl -v -X POST https://bbs.service.cf.internal:8889/v1/ping \
      --cacert /var/vcap/jobs/rep/config/certs/tls_ca.crt \
      --cert /var/vcap/jobs/rep/config/certs/tls.crt --key /var/vcap/jobs/rep/config/certs/tls.key
    *   Trying 10.193.71.24...
    * connect to 10.193.71.24 port 8889 failed: Connection refused
    *   Trying 10.193.71.22...
    * Connected to bbs.service.cf.internal (10.193.71.22) port 8889 (#0)
    * found 1 certificates in /var/vcap/jobs/rep/config/certs/tls_ca.crt
    * found 608 certificates in /etc/ssl/certs
    * ALPN, offering http/1.1
    * SSL connection using TLS1.2 / ECDHE_RSA_AES_256_GCM_SHA384
    *    server certificate verification OK
    *    server certificate status verification SKIPPED
    *    common name: bbs.service.cf.internal (matched)
    *    server certificate expiration date OK
    *    server certificate activation date OK
    *    certificate public key: RSA
    *    certificate version: #3
    *    subject: C=US,O=Pivotal,CN=bbs.service.cf.internal
    *    start date: Fri, 13 Dec 2019 17:53:37 GMT
    *    expire date: Mon, 13 Dec 2021 17:53:37 GMT
    *    issuer: C=US,O=Pivotal
    *    compression: NULL
    * ALPN, server did not agree to a protocol
    > POST /v1/ping HTTP/1.1
    > Host: bbs.service.cf.internal:8889
    > User-Agent: curl/7.47.0
    > Accept: */*
    >
    < HTTP/1.1 200 OK
    < Content-Length: 2
    < Content-Type: application/x-protobuf
    < Date: Mon, 15 Jun 2020 22:22:02 GMT
    <
    * Connection #0 to host bbs.service.cf.internal left intact
    ```

    The above command would fail without `--cert`, `--key` argument because the server (BBS) refuses the handshake if client doesn't provide them. The `--cacert` argument can be omitted if the root CA has been added into OS trusstore.

    To examine which certificates are signed by which root CA (or intermediate CA), please refer `https://OPSMAN/api/v0/deployed/certificates`.

## Homework

Like what you’re learning? Interested to learn more? Here are some additional resources and projects you can use to further your knowledge on certs & TLS.

### Videos

- [A Tour of TLS](https://www.youtube.com/watch?v=yzz3bcnWf7M)

### Books

- [Bulletproof SSL and TLS](https://www.amazon.com/Bulletproof-SSL-TLS-Understanding-Applications/dp/1907117040)
- [What is SSL/TLS Certificate? - SSL/TLS Certificates Explained - AWS](https://aws.amazon.com/what-is/ssl-certificate/)

### Projects

Read through [OpenSSL Certificate Authority](https://jamielinux.com/docs/openssl-certificate-authority/index.html) and follow along to build your own production-grade TLS certificate authority. This is the same process that was used to generate the certificates we use in the MABPBU Support Labs.
