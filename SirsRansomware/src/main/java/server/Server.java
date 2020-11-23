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
import server.domain.file.File;
import server.domain.file.FileRepository;
import server.domain.fileVersion.FileVersion;
import server.domain.fileVersion.FileVersionRepository;
import server.domain.user.User;
import server.domain.user.UserRepository;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.net.InetSocketAddress;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.logging.Logger;


/**
 * Server that manages startup/shutdown of a {@code Greeter} server with TLS enabled.
 */
public class Server {
    private static final Logger logger = Logger.getLogger(Server.class.getName());
    private static final String SIRS_DIR = System.getProperty("user.dir");

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
        SslContextBuilder sslClientContextBuilder = SslContextBuilder.forServer(new java.io.File(certChainFilePath),
                new java.io.File(privateKeyFilePath));
        if (trustCertCollectionFilePath != null) {
            sslClientContextBuilder.trustManager(new java.io.File(trustCertCollectionFilePath));
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
        FileRepository fileRepository;
        FileVersionRepository fileVersionRepository;

        byte[] salt = PBKDF2Main.getNextSalt();

        public ServerImp() {
            try {
                c = new Connector();
                userRepository = new UserRepository(c.getConnection());
                fileRepository = new FileRepository(c.getConnection());
                fileVersionRepository = new FileVersionRepository(c.getConnection());
            } catch ( SQLException e) {
                e.printStackTrace();
            }
        }


        @Override
        public void register(RegisterRequest req, StreamObserver<RegisterReply> responseObserver) {
            RegisterReply reply;
            if (req.getUsername().length() > 15 || req.getUsername().length() == 0)  reply = RegisterReply.newBuilder().setOk("Username too long").build();
            else if( usernameExists(req.getUsername())) reply = RegisterReply.newBuilder().setOk("Duplicate user with username " + req.getUsername()).build();
            else {
                registerUser(req.getUsername(), req.getPassword());
                reply = RegisterReply.newBuilder().setOk("User " + req.getUsername() + " registered successfully").build();
            }
            responseObserver.onNext(reply);
            responseObserver.onCompleted();
        }

        @Override
        public void login(LoginRequest req, StreamObserver<LoginReply> responseObserver) {
            LoginReply reply;
            if (req.getUsername().length() > 15 || req.getUsername().length() == 0 || !usernameExists(req.getUsername()))
                reply = LoginReply.newBuilder().setOkUsername(false).setOkPassword(false).build();
            else {
                if (isCorrectPassword(req.getUsername(),req.getPassword()))
                    reply = LoginReply.newBuilder().setOkUsername(true).setOkPassword(true).build();
                else
                    reply = LoginReply.newBuilder().setOkUsername(true).setOkPassword(false).build();
            }
            responseObserver.onNext(reply);
            responseObserver.onCompleted();
        }


        @Override
        public void push(PushRequest req, StreamObserver<PushReply> responseObserver) {

            ByteString bs = req.getFile();
            System.out.println("Received file from client " + req.getUsername() );
            PushReply reply = null;
            if (isCorrectPassword(req.getUsername(),req.getPassword())) {
                String versionId = UUID.randomUUID().toString();
                byte[] bytes = bs.toByteArray();
                try {
                    FileUtils.writeByteArrayToFile(new java.io.File(SIRS_DIR + "/src/assets/serverFiles/" + versionId), bytes);
                     reply = PushReply.newBuilder().setOk(true).build();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                //REGISTAR FILE
                if(!this.fileRepository.fileExists(req.getUid())){
                    registerFile(req.getUid(),req.getFileName(),req.getUsername(),req.getPartId());
                }
                registerFileVersion(versionId,req.getUid(),req.getUsername());

            } else reply = PushReply.newBuilder().setOk(false).build();

            responseObserver.onNext(reply);
            responseObserver.onCompleted();
        }

        @Override
        public void pull(PullRequest req, StreamObserver<PullReply> responseObserver){
            if (!isCorrectPassword(req.getUsername(),req.getPassword())) {
                responseObserver.onNext(PullReply.newBuilder().setOk(false).build());
                responseObserver.onCompleted();
                return;
            }
            PullReply.Builder reply = PullReply.newBuilder().setOk(true);
            List<File> readableFiles = this.fileRepository.getUserReadableFiles(req.getUsername());
            for ( File file : readableFiles ) {
                System.out.println("Sending file " + file.getName() + " to client " + req.getUsername());
                FileVersion mostRecentVersion = fileVersionRepository.getMostRecentVersion(file.getUid());
                byte[] file_bytes = new byte[0];
                try {
                    file_bytes = Files.readAllBytes(
                            Paths.get(SIRS_DIR + "/src/assets/serverFiles/" + mostRecentVersion.getVersionUid()));
                } catch (IOException e) {
                    e.printStackTrace();
                }
                reply.addUids(file.getUid());
                reply.addFilenames(file.getName());
                reply.addOwners(file.getOwner());
                reply.addPartIds(file.getPartition());
                reply.addFiles(ByteString.copyFrom(
                        file_bytes));
            }
            responseObserver.onNext(reply.build());
            responseObserver.onCompleted();
        }

        @Override
        public void sayHello(HelloRequest req, StreamObserver<HelloReply> responseObserver) {
            HelloReply reply = HelloReply.newBuilder().setMessage("Hello" + req.getName()).build();
            responseObserver.onNext(reply);
            responseObserver.onCompleted();
        }
        @Override
        public void givePermission(GivePermissionRequest req, StreamObserver<GivePermissionReply> responseObserver) {
            GivePermissionReply reply = null;
            if (usernameExists(req.getUsername())){
                if (filenameExists(req.getUid())){
                    giveUserPermission(req.getUsername(), req.getUid(),req.getMode());
                    reply = GivePermissionReply.newBuilder().setOkUsername(true).setOkUid(true).build();

                }
            }
            else reply = GivePermissionReply.newBuilder().setOkUsername(false).setOkUid(false).build();
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

                byte[] userSecret = userRepository.getUserPassword(username);
                byte[] passSalt = userRepository.getPasswordSalt(username);
                int passIterations = userRepository.getPasswordIterations(username);

                PBEKeySpec spec = new PBEKeySpec(chars, passSalt, passIterations, 256 * 8);
                SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                byte[] key = skf.generateSecret(spec).getEncoded();

                return (Arrays.equals(key, userSecret));

            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                e.printStackTrace();
                return false;
            }
        }

        private void registerUser(String name, String password) {
            byte[] secret = generateSecurePassword(password);
            User user = new User(name, secret, this.salt, iterations);
            user.saveInDatabase(this.c);
        }

        private void registerFile(String uid, String filename, String owner, String partId){
            server.domain.file.File file = new server.domain.file.File(uid,owner,filename,partId);
            file.saveInDatabase(this.c);
        }

        private void registerFileVersion(String versionId, String fileId, String creator){
            FileVersion fileVersion = new FileVersion(versionId,fileId,creator, new Date(System.currentTimeMillis()));
            fileVersion.saveInDatabase(this.c);
        }

        private boolean usernameExists(String name) {
            User user = userRepository.getUserByUsername(name);
            return user.getUsername() != null && user.getPassHash() != null;
        }
        private boolean filenameExists(String uid){
            File file = fileRepository.getFileByUID(uid);
            return file.getUid()!= null && file.getName()!=null && file.getPartition()!=null && file.getOwner()!=null;
        }
        private void giveUserPermission(String username, String uid,String mode) {
            userRepository.setUserPermissionFile(username, uid, mode);
        }
    }
}