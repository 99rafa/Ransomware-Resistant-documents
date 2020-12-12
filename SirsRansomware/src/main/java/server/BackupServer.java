package server;


import com.google.protobuf.ByteString;
import io.grpc.Server;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NettyServerBuilder;
import io.grpc.stub.StreamObserver;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContextBuilder;
import org.apache.commons.io.FileUtils;
import proto.*;
import pt.ulisboa.tecnico.sdis.zk.ZKNaming;
import pt.ulisboa.tecnico.sdis.zk.ZKNamingException;

import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Server that manages startup/shutdown of a {@code Greeter} server with TLS enabled.
 */
public class BackupServer {
    private static final String SIRS_DIR = System.getProperty("user.dir");
    private final String zooHost;
    private final String zooPort;
    private final String zooPath;
    private final String host;
    private final String port;
    private X509Certificate certChain = null;
    private PrivateKey privateKey = null;
    private X509Certificate trustCertCollection = null;
    private Server server;
    private ZKNaming zkNaming;

    public BackupServer(String id,
                        String partId,
                        String zooPort,
                        String zooHost,
                        String port,
                        String host) {
        this.zooPort = zooPort;
        this.zooHost = zooHost;
        this.zooPath = "/sirs/ransomware/backups/" + partId + "_" + id;
        this.host = host;
        this.port = port;

        KeyStore ks = null;
        String passwd = null;

        Console console = System.console();

        try {
            ks = KeyStore.getInstance("PKCS12");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        boolean wrongPassword = true;

        while (wrongPassword) {
            passwd = new String(console.readPassword("Enter private Key keyStore password: "));
            try {
                assert ks != null;
                ks.load(new FileInputStream("src/assets/keyStores/privateKeyServerKeyStore.p12"), passwd.toCharArray());
                privateKey = (PrivateKey) ks.getKey("server-private-key", passwd.toCharArray());
                wrongPassword = false;
            } catch (IOException e) {
                System.err.println("Error: Incorrect password");
            } catch (NoSuchAlgorithmException | CertificateException | KeyStoreException | UnrecoverableKeyException e) {
                e.printStackTrace();
            }
        }


        KeyStore trustCertKeyStore = null;
        try {
            trustCertKeyStore = KeyStore.getInstance("PKCS12");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        wrongPassword = true;

        while (wrongPassword) {
            passwd = new String(console.readPassword("Enter trust cert keyStore password: "));
            try {
                assert trustCertKeyStore != null;
                trustCertKeyStore.load(new FileInputStream("src/assets/keyStores/trustCertsServerKeyStore.p12"), passwd.toCharArray());
                certChain = (X509Certificate) trustCertKeyStore.getCertificate("server-cert");
                wrongPassword = false;
            } catch (IOException e) {
                System.err.println("Error: Incorrect password");
            } catch (NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
                e.printStackTrace();
            }
        }


        KeyStore trustStore = null;
        try {
            trustStore = KeyStore.getInstance("PKCS12");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        wrongPassword = true;

        while (wrongPassword) {
            passwd = new String(console.readPassword("Enter trustStore password: "));
            try {
                assert trustStore != null;
                trustStore.load(new FileInputStream("src/assets/keyStores/truststore.p12"), passwd.toCharArray());
                trustCertCollection = (X509Certificate) trustStore.getCertificate("ca-cert");
                wrongPassword = false;
            } catch (IOException e) {
                System.err.println("Error: Incorrect password");
            } catch (NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
                e.printStackTrace();
            }
        }

    }

    /**
     * Main launches the server from the command line.
     */
    public static void main(String[] args) throws IOException, InterruptedException {

        if (args.length != 6) {
            System.out.println(
                    "USAGE: ID partID zooHost zooPort host port");
            System.exit(0);
        }

        final BackupServer server = new BackupServer(
                args[0],
                args[1],
                args[2],
                args[3],
                args[4],
                args[5]);
        server.start();
        server.blockUntilShutdown();
    }

    private void addToZooKeeper() {

        this.zkNaming = new ZKNaming(zooHost, zooPort);
        try {
            this.zkNaming.rebind(this.zooPath, host, this.port);
        } catch (ZKNamingException e) {
            e.printStackTrace();
        }
    }

    private void removeFromZooKeeper() {
        if (this.zkNaming != null) {
            // remove
            try {
                this.zkNaming.unbind(this.zooPath, host, this.port);
            } catch (ZKNamingException e) {
                e.printStackTrace();
            }
        }
    }

    private SslContextBuilder getSslContextBuilder() {
        SslContextBuilder sslClientContextBuilder = SslContextBuilder.forServer(privateKey, certChain
                );
        if (trustCertCollection!= null) {
            sslClientContextBuilder.trustManager(trustCertCollection);
            sslClientContextBuilder.clientAuth(ClientAuth.REQUIRE);
        }
        return GrpcSslContexts.configure(sslClientContextBuilder);
    }

    private void start() throws IOException {
        server = NettyServerBuilder.forAddress(new InetSocketAddress(host, Integer.parseInt(port)))
                .addService(new BackupServerImpl())
                .sslContext(getSslContextBuilder().build())
                .build()
                .start();
        addToZooKeeper();
        System.out.println("Server started, listening on " + this.port);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            // Use stderr here since the logger may have been reset by its JVM shutdown hook.
            System.err.println("*** shutting down gRPC server since JVM is shutting down");
            removeFromZooKeeper();
            BackupServer.this.stop();
            System.err.println("*** server shut down");
        }));
    }

    private void stop() {
        if (server != null) {
            server.shutdown();
        }
    }

    /**
     * Await termination on the main thread since the grpc library uses daemon threads.
     */
    private void blockUntilShutdown() throws InterruptedException {
        if (server != null) {
            server.awaitTermination();
        }
    }

    static class BackupServerImpl extends BackupServerGrpc.BackupServerImplBase {

        @Override
        public void getBackup(GetBackupRequest request, StreamObserver<GetBackupReply> responseObserver) {
            byte[] file_bytes = new byte[0];
            try {
                file_bytes = Files.readAllBytes(
                        Paths.get(SIRS_DIR + "/src/assets/backupFiles/" + request.getUid()));
            } catch (IOException e) {
                e.printStackTrace();
            }

            GetBackupReply getBackupReply = GetBackupReply
                    .newBuilder()
                    .setFile(ByteString.copyFrom(file_bytes))
                    .build();

            responseObserver.onNext(getBackupReply);
            responseObserver.onCompleted();
        }

        @Override
        public void backupFile(BackupFileRequest request, StreamObserver<BackupFileReply> responseObserver) {
            System.out.println("Receiving backup of file : " + request.getUid());
            BackupFileReply backupFileReply;
            byte[] bytes = request.getFile().toByteArray();
            try {
                FileUtils.writeByteArrayToFile(new java.io.File(SIRS_DIR + "/src/assets/backupFiles/" + request.getUid()), bytes);
                backupFileReply = BackupFileReply.newBuilder().setOk(true).build();
            } catch (IOException e) {
                backupFileReply = BackupFileReply.newBuilder().setOk(false).build();
                e.printStackTrace();
            }


            responseObserver.onNext(backupFileReply);
            responseObserver.onCompleted();
        }
    }
}
