package com.example.sslbundletest;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.stereotype.Component;

import javax.net.ssl.X509TrustManager;
import java.security.*;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

@SpringBootApplication
public class SslbundleTestApplication {

    public static void main(String[] args) {
        SpringApplication.run(SslbundleTestApplication.class, args);
    }

}

@Component
class SelfSignedSslBundleReader {
    private final X509Certificate[] serverCertificateChain;
    private final X509Certificate serverCertificate;

    private final KeyPair serverKeyPair;
    private final X509TrustManager[] x509TrustManagers;
    private final List<X509Certificate> acceptedIssuers;

    SelfSignedSslBundleReader(SslBundles sslBundles, @Value("${bundle.name:self-signed}") String bundleName) throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException, CertificateParsingException {

        SslBundle sslBundle = sslBundles.getBundle(bundleName);

        KeyStore keyStore = sslBundle.getStores().getKeyStore();
        char[] keyPassArray = sslBundle.getStores().getKeyStorePassword() !=null ? sslBundle.getStores().getKeyStorePassword().toCharArray() : null;

        Iterator<String> aliases = keyStore.aliases().asIterator();
        // Assumes only 1 alias is defined
        String alias = aliases.next();

        List<X509Certificate> serverCertificateChain = new ArrayList<>();
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        certificate.getSubjectAlternativeNames();

        serverCertificateChain.add(certificate);

        List<X509Certificate> acceptedIssuers = new ArrayList<>();
        List<X509TrustManager> trustManagers = new ArrayList<>();

        Arrays.stream(sslBundle.getManagers().getTrustManagers()).forEach(trustManager -> {
            if (trustManager instanceof X509TrustManager x509TrustManager){
                trustManagers.add(x509TrustManager);
                acceptedIssuers.addAll(Arrays.asList(x509TrustManager.getAcceptedIssuers()));
            }
        });

        this.serverCertificateChain = serverCertificateChain.toArray(new X509Certificate[0]);
        this.serverCertificate = certificate;

        this.serverKeyPair = new KeyPair(serverCertificate.getPublicKey(), (PrivateKey) keyStore.getKey(alias, keyPassArray));
        this.acceptedIssuers = acceptedIssuers;
        this.x509TrustManagers = trustManagers.toArray(new X509TrustManager[0]);
    }

    public X509Certificate[] getServerCertificateChain() {
        return serverCertificateChain;
    }

    public X509Certificate getServerCertificate() {
        return serverCertificate;
    }

    public KeyPair getServerKeyPair() {
        return serverKeyPair;
    }

    public X509TrustManager[] getX509TrustManagers() {
        return x509TrustManagers;
    }

    public List<X509Certificate> getAcceptedIssuers() {
        return acceptedIssuers;
    }
}