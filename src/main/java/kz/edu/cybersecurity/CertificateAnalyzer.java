package kz.edu.cybersecurity;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class CertificateAnalyzer {

    public X509Certificate analyze(Path certificatePath) throws Exception {
        try (InputStream input = Files.newInputStream(certificatePath)) {
            CertificateFactory factory =
                    CertificateFactory.getInstance("X.509");

            return (X509Certificate) factory.generateCertificate(input);
        }
    }

    public void printCertificateInfo(Path certificatePath) throws Exception {
        X509Certificate certificate = analyze(certificatePath);

        System.out.println("Subject: " + certificate.getSubjectX500Principal());
        System.out.println("Issuer: " + certificate.getIssuerX500Principal());
        System.out.println("Valid from: " + certificate.getNotBefore());
        System.out.println("Valid until: " + certificate.getNotAfter());
        System.out.println("Algorithm: " + certificate.getSigAlgName());
    }
}
