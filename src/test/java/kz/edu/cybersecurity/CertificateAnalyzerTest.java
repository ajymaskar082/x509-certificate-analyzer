package kz.edu.cybersecurity;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
class CertificateAnalyzerTest {

    @Test
    void analyzerObjectCanBeCreated() {
        CertificateAnalyzer analyzer = new CertificateAnalyzer();
        assertNotNull(analyzer);
    }

    @Test
    void invalidCertificatePathThrowsException() {
        CertificateAnalyzer analyzer = new CertificateAnalyzer();

        assertThrows(Exception.class, () ->
                analyzer.analyze(
                        java.nio.file.Path.of("missing-certificate.pem")
                )
        );
    }

    @Test
    void emptyFileThrowsException(@TempDir Path tempDir) throws Exception {
        Path file = Files.createFile(tempDir.resolve("empty.pem"));

        CertificateAnalyzer analyzer = new CertificateAnalyzer();

        assertThrows(Exception.class, () -> analyzer.analyze(file));
    }

    @Test
    void invalidCertificateThrowsException(@TempDir Path tempDir)
            throws Exception {
        Path file = tempDir.resolve("invalid.pem");
        Files.writeString(file, "This is not a valid certificate");

        CertificateAnalyzer analyzer = new CertificateAnalyzer();

        assertThrows(Exception.class, () -> analyzer.analyze(file));
    }

    @Test
    void malformedPemThrowsException(@TempDir Path tempDir)
            throws Exception {
        Path file = tempDir.resolve("malformed.pem");
        Files.writeString(file,
                "-----BEGIN CERTIFICATE-----\ninvalid-data\n"
                        + "-----END CERTIFICATE-----");

        CertificateAnalyzer analyzer = new CertificateAnalyzer();

        assertThrows(Exception.class, () -> analyzer.analyze(file));
    }

    @Test
    void whitespaceOnlyFileThrowsException(@TempDir Path tempDir)
            throws Exception {
        Path file = tempDir.resolve("spaces.pem");
        Files.writeString(file, "   \n   ");

        CertificateAnalyzer analyzer = new CertificateAnalyzer();

        assertThrows(Exception.class, () -> analyzer.analyze(file));
    }

    @Test
    void missingPemBoundaryThrowsException(@TempDir Path tempDir)
            throws Exception {
        Path file = tempDir.resolve("no-boundary.pem");
        Files.writeString(file, "invalid certificate data");

        CertificateAnalyzer analyzer = new CertificateAnalyzer();

        assertThrows(Exception.class, () -> analyzer.analyze(file));
    }

    @Test
    void incompletePemThrowsException(@TempDir Path tempDir)
            throws Exception {
        Path file = tempDir.resolve("incomplete.pem");
        Files.writeString(file, "-----BEGIN CERTIFICATE-----");

        CertificateAnalyzer analyzer = new CertificateAnalyzer();

        assertThrows(Exception.class, () -> analyzer.analyze(file));
    }

    @Test
    void randomTextFileThrowsException(@TempDir Path tempDir)
            throws Exception {
        Path file = tempDir.resolve("random.txt");
        Files.writeString(file, "Hello, this is a test file.");

        CertificateAnalyzer analyzer = new CertificateAnalyzer();

        assertThrows(Exception.class, () -> analyzer.analyze(file));
    }

    @Test
    void directoryInsteadOfFileThrowsException(@TempDir Path tempDir)
            throws Exception {
        CertificateAnalyzer analyzer = new CertificateAnalyzer();

        assertThrows(Exception.class, () -> analyzer.analyze(tempDir));
    }

    @Test
    void nullPathThrowsException() {
        CertificateAnalyzer analyzer = new CertificateAnalyzer();

        assertThrows(Exception.class, () -> analyzer.analyze(null));
    }

    @Test
    void fileWithOnlyPemHeaderThrowsException(@TempDir Path tempDir)
            throws Exception {
        Path file = tempDir.resolve("header-only.pem");
        Files.writeString(file, "-----BEGIN CERTIFICATE-----");

        CertificateAnalyzer analyzer = new CertificateAnalyzer();

        assertThrows(Exception.class, () -> analyzer.analyze(file));
    }

    @Test
    void nonCertificatePemContentThrowsException(@TempDir Path tempDir)
            throws Exception {
        Path file = tempDir.resolve("wrong-content.pem");
        Files.writeString(file,
                "-----BEGIN CERTIFICATE-----\n"
                        + "YWJjZGVm\n"
                        + "-----END CERTIFICATE-----");

        CertificateAnalyzer analyzer = new CertificateAnalyzer();

        assertThrows(Exception.class, () -> analyzer.analyze(file));
    }

    @Test
    void textFileWithPemExtensionThrowsException(@TempDir Path tempDir)
            throws Exception {
        Path file = tempDir.resolve("not-a-certificate.pem");
        Files.writeString(file, "ordinary text, not a certificate");

        CertificateAnalyzer analyzer = new CertificateAnalyzer();

        assertThrows(Exception.class, () -> analyzer.analyze(file));
    }

    @Test
    void repeatedInvalidInputStillThrowsException(@TempDir Path tempDir)
            throws Exception {
        Path file = tempDir.resolve("repeated-invalid.pem");
        Files.writeString(file, "invalid");

        CertificateAnalyzer analyzer = new CertificateAnalyzer();

        assertThrows(Exception.class, () -> analyzer.analyze(file));
        assertThrows(Exception.class, () -> analyzer.analyze(file));
    }

}
