package server;


import PBKDF2.PBKDF2Main;
import com.google.protobuf.ByteString;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NettyServerBuilder;
import io.grpc.stub.StreamObserver;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContextBuilder;
import org.apache.commons.io.FileUtils;
import proto.*;
import pt.ulisboa.tecnico.sdis.zk.ZKNaming;
import pt.ulisboa.tecnico.sdis.zk.ZKNamingException;
import server.database.Connector;
import server.domain.user.User;
import server.domain.user.UserRepository;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.net.InetSocketAddress;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.logging.Logger;


/**
 * Server that manages startup/shutdown of a {@code Greeter} server with TLS enabled.
 */
public class Server {
    private static final Logger logger = Logger.getLogger(Server.class.getName());

    private io.grpc.Server server;

    private ZKNaming zkNaming;
    private final String id;
    private final String zooPort;
    private final String zooHost;
    private final String zooPath;
    private final String port;
    private final String host;
    private final String certChainFilePath;
    private final String privateKeyFilePath;
    private final String trustCertCollectionFilePath;

    public Server(String id,
                  String zooPort,
                  String zooHost,
                  String port,
                  String host,
                  String certChainFilePath,
                  String privateKeyFilePath,
                  String trustCertCollectionFilePath) {
        this.id = id;
        this.zooPort = zooPort;
        this.zooHost = zooHost;
        this.zooPath = "/sirs/ransomware/servers/" + id;
        this.host = host;
        this.port = port;
        this.certChainFilePath = certChainFilePath;
        this.privateKeyFilePath = privateKeyFilePath;
        this.trustCertCollectionFilePath = trustCertCollectionFilePath;
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
                .addService(new ServerImp())
                .sslContext(getSslContextBuilder().build())
                .build()
                .start();
        //Adds server to naming server
        addToZooKeeper();
        logger.info("Server started, listening on " + port);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            // Use stderr here since the logger may have been reset by its JVM shutdown hook.
            System.err.println("*** shutting down gRPC server since JVM is shutting down");
            Server.this.stop();
            //removes server from naming server
            removeFromZooKeeper();
            System.err.println("*** server shut down");
        }));
    }

    private void stop() {
        if (server != null) {
            server.shutdown();
        }
    }

    private void addToZooKeeper(){

        this.zkNaming = new ZKNaming(zooHost, zooPort);
        try {
            zkNaming.rebind(this.zooPath, host, this.port);
        } catch (ZKNamingException e) {
            e.printStackTrace();
        }
    }

    private void removeFromZooKeeper(){
        if (zkNaming != null) {
            // remove
            try {
                zkNaming.unbind(this.zooPath, host, this.port);
            } catch (ZKNamingException e) {
                e.printStackTrace();
            }
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

        if (args.length < 7 || args.length > 8) {
            System.out.println(
                    "USAGE: ServerTls id zooHost zooPort host port certChainFilePath privateKeyFilePath " +
                            "[trustCertCollectionFilePath]\n  Note: You only need to supply trustCertCollectionFilePath if you want " +
                            "to enable Mutual TLS.");
            System.exit(0);
        }

        final Server server = new Server(
                args[0],
                args[1],
                args[2],
                args[3],
                args[4],
                args[5],
                args[6],
                args.length == 8 ? args[7] : null);

        server.start();
        server.blockUntilShutdown();
    }

    static class ServerImp extends ServerGrpc.ServerImplBase {

        public final static int iterations = 10000;
        Connector c;
        UserRepository userRepository;
        byte[] salt = PBKDF2Main.getNextSalt();

        public ServerImp() {
            try {
                c = new Connector();
                userRepository = new UserRepository(c.getConnection());
            } catch ( SQLException e) {
                e.printStackTrace();
            }
        }


        @Override
        public void register(RegisterRequest req, StreamObserver<RegisterReply> responseObserver) {
            RegisterReply reply;
            if (req.getName().length() > 15)  reply = RegisterReply.newBuilder().setOk("Username too long").build();
            else {
                registerUser(req.getName(), req.getPassword());
                reply = RegisterReply.newBuilder().setOk("User " + req.getName() + " registered successfully").build();
            }
            responseObserver.onNext(reply);
            responseObserver.onCompleted();
        }

        @Override
        public void fileTransfer(FileTransferRequest req, StreamObserver<FileTransferReply> responseObserver) {

            ByteString bs = req.getFile();
            System.out.println("Received file from client " + req.getUsername() );

            if (isCorrectPassword(req.getUsername(),req.getPassword())) {
                System.out.println("entrou aqui");
            }

            byte[] bytes = bs.toByteArray();
            try {
                FileUtils.writeByteArrayToFile(new File("test"), bytes);
            } catch (IOException e) {
                e.printStackTrace();
            }

            FileTransferReply reply = FileTransferReply.newBuilder().setOk(true).build();
            responseObserver.onNext(reply);
            responseObserver.onCompleted();
        }

        private byte[] generateSecurePassword(String password) {
            byte[] key = null;
            try {
                char[] chars = password.toCharArray();
                //rafa edit: this is just to demonstrate how to generate a PBKDF2 password-based kdf
                // because the salt needs to be the same
                //byte[] salt = PBKDF2Main.getNextSalt();

                PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 256 * 8);
                SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                key = skf.generateSecret(spec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                e.printStackTrace();
            }
            return key;
        }

        private boolean isCorrectPassword(String username, String password) {

            try {

                char[] chars = password.toCharArray();
                //rafa edit: this is just to demonstrate how to generate a PBKDF2 password-based kdf
                // because the salt needs to be the same
                //byte[] salt = PBKDF2Main.getNextSalt();

                PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 256 * 8);
                SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                byte[] key = skf.generateSecret(spec).getEncoded();

                byte[] userSecret = userRepository.getUserPassword(username);
                return (Arrays.equals(key, userSecret));

            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                e.printStackTrace();
                return false;
            }
        }

        private void registerUser(String name, String password) {
            try {
                Connector c = new Connector();
                byte[] secret = generateSecurePassword(password);
                User user = new User(name, secret);
                user.saveInDatabase(c);
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }
}