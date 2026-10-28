package kz.edu.cybersecurity;

import java.nio.file.Path;

public class Main {
    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println(
                    "Usage: java Main <certificate.pem>"
            );
            return;
        }

        try {
            CertificateAnalyzer analyzer = new CertificateAnalyzer();
            analyzer.printCertificateInfo(Path.of(args[0]));
        } catch (Exception e) {
            System.err.println("Error reading certificate: "
                    + e.getMessage());
        }
    }
}