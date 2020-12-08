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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.logging.Logger;

/**
 * Server that manages startup/shutdown of a {@code Greeter} server with TLS enabled.
 */
public class BackupServer {
    private static final String SIRS_DIR = System.getProperty("user.dir");
    private Server server;

    private final String id;
    private final String partId;
    private final String zooHost;
    private final String zooPort;
    private final String zooPath;
    private final String host;
    private final String port;
    private final String certChainFilePath;
    private final String privateKeyFilePath;
    private final String trustCertCollectionFilePath;
    private ZKNaming zkNaming;

    public BackupServer(String id,
                  String partId,
                  String zooPort,
                  String zooHost,
                  String port,
                  String host,
                  String certChainFilePath,
                  String privateKeyFilePath,
                  String trustCertCollectionFilePath) {
        this.id = id;
        this.partId = partId;
        this.zooPort = zooPort;
        this.zooHost = zooHost;
        this.zooPath = "/sirs/ransomware/backups/" + partId + "_" + id;
        this.host = host;
        this.port = port;
        this.certChainFilePath = certChainFilePath;
        this.privateKeyFilePath = privateKeyFilePath;
        this.trustCertCollectionFilePath = trustCertCollectionFilePath;

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
        SslContextBuilder sslClientContextBuilder = SslContextBuilder.forServer(new File(certChainFilePath),
                new File(privateKeyFilePath));
        if (trustCertCollectionFilePath != null) {
            sslClientContextBuilder.trustManager(new File(trustCertCollectionFilePath));
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
        Runtime.getRuntime().addShutdownHook(new Thread() {
            @Override
            public void run() {
                // Use stderr here since the logger may have been reset by its JVM shutdown hook.
                System.err.println("*** shutting down gRPC server since JVM is shutting down");
                removeFromZooKeeper();
                BackupServer.this.stop();
                System.err.println("*** server shut down");
            }
        });
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

    /**
     * Main launches the server from the command line.
     */
    public static void main(String[] args) throws IOException, InterruptedException {

        if ( args.length != 9) {
            System.out.println(
                    "USAGE: ID partID zooHost zooPort host port certChainFilePath privateKeyFilePath " +
                            "[trustCertCollectionFilePath]\n  Note: You only need to supply trustCertCollectionFilePath if you want " +
                            "to enable Mutual TLS.");
            System.exit(0);
        }

        final BackupServer server = new BackupServer(
                args[0],
                args[1],
                args[2],
                args[3],
                args[4],
                args[5],
                args[6],
                args[7],
                args[8]);
        server.start();
        server.blockUntilShutdown();
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
