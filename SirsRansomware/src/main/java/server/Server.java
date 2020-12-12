package server;


import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.NettyServerBuilder;
import io.grpc.stub.StreamObserver;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.apache.commons.io.FileUtils;
import proto.*;
import pt.ulisboa.tecnico.sdis.zk.ZKNaming;
import pt.ulisboa.tecnico.sdis.zk.ZKNamingException;
import pt.ulisboa.tecnico.sdis.zk.ZKRecord;
import server.database.Connector;
import server.domain.file.File;
import server.domain.file.FileRepository;
import server.domain.fileVersion.FileVersion;
import server.domain.fileVersion.FileVersionRepository;
import server.domain.user.User;
import server.domain.user.UserRepository;

import javax.net.ssl.SSLException;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.logging.Logger;
import java.util.stream.Collectors;


/**
 * Server that manages startup/shutdown of a server with TLS enabled.
 */
public class Server {

    private static final Logger logger = Logger.getLogger(Server.class.getName());
    private static final String SIRS_DIR = System.getProperty("user.dir");
    private static ZKNaming zkNaming;
    private final String zooPort;
    private final String zooHost;
    private final String zooPath;
    private final String port;
    private final String host;
    private X509Certificate certChain = null;
    private PrivateKey privateKey = null;
    private X509Certificate trustCertCollection = null;
    private final String user;
    private final String pass;

    private io.grpc.Server server;

    public Server(String user,
                  String pass,
                  String zooPort,
                  String zooHost,
                  String port,
                  String host) throws Exception {
        this.user = user;
        this.pass = pass;
        this.zooPort = zooPort;
        this.zooHost = zooHost;
        this.zooPath = "/sirs/ransomware/server";
        this.host = host;
        this.port = port;


        Console console = System.console();
        String passwd = null;
        KeyStore ks = null;
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
            } catch (NoSuchAlgorithmException | CertificateException e) {
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
            } catch (NoSuchAlgorithmException | CertificateException e) {
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
            } catch (NoSuchAlgorithmException | CertificateException e) {
                e.printStackTrace();
            }
        }
    }

    /*private static X509Certificate readCertificate(String path) {
        CertificateFactory fact = null;
        FileInputStream is = null;
        try {
            fact = CertificateFactory.getInstance("X.509");
             is = new FileInputStream(path);
            return ((X509Certificate) fact.generateCertificate(is));
        } catch (CertificateException | FileNotFoundException e) {
            e.printStackTrace();
        }
        return null;

    }*/


    private static SslContext buildSslContext(X509Certificate trustCertCollection,
                                              X509Certificate clientCertChain,
                                              PrivateKey key) throws SSLException {
        SslContextBuilder builder = GrpcSslContexts.forClient();
        if (trustCertCollection!= null) {
            builder.trustManager(trustCertCollection);
        }
        if (clientCertChain != null && key != null) {
            builder.keyManager(key, clientCertChain);
        }
        return builder.build();
    }

    /**
     * Main launches the server from the command line.
     */
    public static void main(String[] args) throws Exception {

        if (args.length != 6) {
            System.out.println(
                    "USAGE: ServerTls dbuser dbpass zooHost zooPort host port");
            System.exit(0);
        }


        final Server server = new Server(
                args[0],
                args[1],
                args[2],
                args[3],
                args[4],
                args[5]
        );
        server.start();

        server.blockUntilShutdown();


    }

    private SslContextBuilder getSslContextBuilder() {
        SslContextBuilder sslClientContextBuilder = SslContextBuilder.forServer(privateKey,
                 certChain);
        if (trustCertCollection != null) {
            sslClientContextBuilder.trustManager(trustCertCollection);
            sslClientContextBuilder.clientAuth(ClientAuth.REQUIRE);
        }
        return GrpcSslContexts.configure(sslClientContextBuilder);
    }

    private void start() throws IOException {
        server = NettyServerBuilder.forAddress(new InetSocketAddress(host, Integer.parseInt(port)))
                .addService(new ServerImp(
                        this.user,
                        this.pass,
                        this.certChain,
                        this.privateKey,
                        this.trustCertCollection)
                )
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

    private void addToZooKeeper() {

        zkNaming = new ZKNaming(this.zooHost, this.zooPort);
        try {
            zkNaming.rebind(this.zooPath, this.host, this.port);
        } catch (ZKNamingException e) {
            e.printStackTrace();
        }
    }

    private void removeFromZooKeeper() {
        if (zkNaming != null) {
            // remove
            try {
                zkNaming.unbind(this.zooPath, this.host, this.port);
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

    static class ServerImp extends ServerGrpc.ServerImplBase {
        private final static int ITERATIONS = 10000;
        private X509Certificate certChain;
        private PrivateKey privateKey;
        private X509Certificate trustCertCollection;
        Connector c;
        UserRepository userRepository;
        FileRepository fileRepository;
        FileVersionRepository fileVersionRepository;


        public ServerImp(String user,
                         String pass,
                         X509Certificate certChain,
                         PrivateKey privateKey,
                         X509Certificate trustCertCollection
        ) {
            this.certChain = certChain;
            this.privateKey = privateKey;
            this.trustCertCollection = trustCertCollection;
            try {
                c = new Connector(user,pass);
                userRepository = new UserRepository(c.getConnection());
                fileRepository = new FileRepository(c.getConnection());
                fileVersionRepository = new FileVersionRepository(c.getConnection());
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }

        @Override
        public void revertMostRecentVersion(RevertMostRecentVersionRequest request, StreamObserver<RevertMostRecentVersionReply> responseObserver) {

            System.out.println();
            System.out.println("Received revert most recent version request");

            try {
                System.out.println();
                List<String> servers = getZooPaths("/sirs/ransomware/backups");
                for (String server : servers) {
                    String pair = server.split("/")[4];
                    String part = pair.split("_")[0];
                    String id = pair.split("_")[1];
                    if (part.equals(request.getPartId())) {
                        System.out.println("Rolling back to version " + request.getVersionUid() + " of file " + request.getFileUid());
                        byte[] file = getBackup(server, request.getVersionUid()).toByteArray();
                        FileUtils.writeByteArrayToFile(new java.io.File(SIRS_DIR + "/src/assets/serverFiles/" + request.getFileUid()), file);
                        break;
                    }

                }

            } catch (IOException e) {
                e.printStackTrace();
            }

            RevertMostRecentVersionReply reply = RevertMostRecentVersionReply.newBuilder().setOk(true).build();
            responseObserver.onNext(reply);
            responseObserver.onCompleted();
        }

        @Override
        public void listFileVersions(ListFileVersionsRequest request, StreamObserver<ListFileVersionsReply> responseObserver) {
            List<FileVersion> versions = this.fileVersionRepository
                    .getFileVersions(request.getFileUid());

            ListFileVersionsReply reply = ListFileVersionsReply
                    .newBuilder()
                    .addAllDates(
                            versions.stream()
                                    .map(l ->
                                    {
                                        DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss aa");
                                        return dateFormat.format(l.getDate());
                                    })
                                    .collect(Collectors.toList())
                    )
                    .addAllFileIds(
                            versions.stream()
                                    .map(FileVersion::getFileUid)
                                    .collect(Collectors.toList())
                    )
                    .addAllVersionsUids(
                            versions.stream()
                                    .map(FileVersion::getVersionUid)
                                    .collect(Collectors.toList())
                    )
                    .build();
            responseObserver.onNext(reply);
            responseObserver.onCompleted();
        }

        @Override
        public void retrieveHealthyVersions(RetrieveHealthyVersionsRequest request, StreamObserver<RetrieveHealthyVersionsReply> responseObserver) {

            System.out.println();
            System.out.println("Received retrieve healthy versions request");

            List<String> servers = getZooPaths("/sirs/ransomware/backups");
            List<ByteString> backup_versions = new ArrayList<>();
            for (String backup : servers) {
                try {
                    backup_versions.add(getBackup(backup, request.getUid()));
                } catch (SSLException e) {
                    e.printStackTrace();
                }
            }
            System.out.println("Retrieving healthy versions of file " + request.getUid());
            RetrieveHealthyVersionsReply reply = RetrieveHealthyVersionsReply
                    .newBuilder()
                    .addAllFiles(backup_versions)
                    .build();

            responseObserver.onNext(reply);
            responseObserver.onCompleted();
        }

        @Override
        public void healCorruptedVersion(HealCorruptedVersionRequest request, StreamObserver<HealCorruptedVersionReply> responseObserver) {

            System.out.println();
            System.out.println("Received heal corrupted version request");

            try {
                System.out.println("Healing corrupted version " + request.getVersionUid() + " of file " + request.getFileUid());
                FileUtils.writeByteArrayToFile(new java.io.File(SIRS_DIR + "/src/assets/serverFiles/" + request.getFileUid()), request.getFile().toByteArray());
                replicateFile(request.getPartId(), request.getFile(), request.getVersionUid());
            } catch (IOException e) {
                e.printStackTrace();
            }


            HealCorruptedVersionReply reply = HealCorruptedVersionReply
                    .newBuilder()
                    .setOk(true)
                    .build();
            responseObserver.onNext(reply);
            responseObserver.onCompleted();
        }

        @Override
        public void salt(SaltRequest request, StreamObserver<SaltReply> responseObserver) {
            User user = userRepository.getUserByUsername(request.getUsername());
            SaltReply reply = SaltReply.newBuilder().setSalt(ByteString.copyFrom(user.getSalt())).build();

            responseObserver.onNext(reply);
            responseObserver.onCompleted();
        }

        @Override
        public void register(RegisterRequest req, StreamObserver<RegisterReply> responseObserver) {
            System.out.println();
            System.out.println("Received register request for user " + req.getUsername());

            RegisterReply reply;
            if (req.getUsername().length() > 15 || req.getUsername().length() == 0)
                reply = RegisterReply.newBuilder().setOk("Username must have between 1 and 15 characters").build();
            else if (usernameExists(req.getUsername()))
                reply = RegisterReply.newBuilder().setOk("Duplicate user with username " + req.getUsername()).build();
            else {
                System.out.println("Registering user " + req.getUsername());
                registerUser(req.getUsername(), req.getPassword().toByteArray(), req.getSalt().toByteArray(), req.getPublicKey().toByteArray());
                reply = RegisterReply.newBuilder().setOk("User " + req.getUsername() + " registered successfully").build();
            }
            responseObserver.onNext(reply);
            responseObserver.onCompleted();
        }

        public void usernameExists(UsernameExistsRequest req, StreamObserver<UsernameExistsReply> responseObserver) {

            UsernameExistsReply reply;
            if (usernameExists(req.getUsername())) {
                reply = UsernameExistsReply.newBuilder().setOkUsername(true).build();
            } else {
                reply = UsernameExistsReply.newBuilder().setOkUsername(false).build();
            }
            responseObserver.onNext(reply);
            responseObserver.onCompleted();
        }

        @Override
        public void getPublicKeysByFile(GetPublicKeysByFileRequest request, StreamObserver<GetPublicKeysByFileReply> responseObserver) {
            GetPublicKeysByFileReply reply = GetPublicKeysByFileReply
                    .newBuilder()
                    .addAllKeys(
                            fileRepository.getPublicKeysByFile(request.getFileUid())
                                    .stream()
                                    .map(ByteString::copyFrom)
                                    .collect(Collectors.toList())
                    )
                    .build();
            responseObserver.onNext(reply);
            responseObserver.onCompleted();
        }

        @Override
        public void getPublicKeysByUsernames(GetPublicKeysByUsernamesRequest request, StreamObserver<GetPublicKeysByUsernamesReply> responseObserver) {
            GetPublicKeysByUsernamesReply reply = GetPublicKeysByUsernamesReply
                    .newBuilder()
                    .addAllKeys(
                            userRepository.getPublicKeysByUsernames(request.getUsernamesList())
                                    .stream()
                                    .map(ByteString::copyFrom)
                                    .collect(Collectors.toList())
                    )
                    .build();
            responseObserver.onNext(reply);
            responseObserver.onCompleted();
        }

        @Override
        public void getFileOwnerPublicKey(GetFileOwnerPublicKeyRequest request, StreamObserver<GetFileOwnerPublicKeyReply> responseObserver) {
            GetFileOwnerPublicKeyReply reply = GetFileOwnerPublicKeyReply
                    .newBuilder()
                    .setPublicKey(ByteString.copyFrom(fileRepository.getFileOwnerPublicKey(request.getUid())))
                    .build();

            responseObserver.onNext(reply);
            responseObserver.onCompleted();
        }

        @Override
        public void push(PushRequest req, StreamObserver<PushReply> responseObserver) {

            ByteString bs = req.getFile();
            System.out.println();
            System.out.println("Received file " + req.getFileName() + " from client " + req.getUsername());
            PushReply reply = null;
            String versionId = UUID.randomUUID().toString();
            byte[] bytes = bs.toByteArray();
            try {
                FileUtils.writeByteArrayToFile(new java.io.File(SIRS_DIR + "/src/assets/serverFiles/" + req.getUid()), bytes);
                reply = PushReply.newBuilder().setOk(true).build();
            } catch (IOException e) {
                e.printStackTrace();
            }
            //REGISTER FILE
            if (!this.fileRepository.fileExists(req.getUid())) {
                registerFile(req.getUid(), req.getFileName(), req.getUsername(), req.getPartId(), req.getAESEncrypted().toByteArray(), req.getIv().toByteArray());
            }
            registerFileVersion(versionId, req.getUid(), req.getUsername(), req.getDigitalSignature().toByteArray());
            //REPLICATE CHANGE TO BACKUPS
            try {
                replicateFile(req.getPartId(), req.getFile(), versionId);

            } catch (SSLException e) {
                e.printStackTrace();
            } finally {
                responseObserver.onNext(reply);
                responseObserver.onCompleted();
            }

        }

        @Override
        public void pullAll(PullAllRequest req, StreamObserver<PullReply> responseObserver) {

            System.out.println();
            System.out.println("Pull All request received");

            PullReply.Builder reply = PullReply.newBuilder();
            List<File> readableFiles = this.fileRepository.getUserReadableFiles(req.getUsername());
            for (File file : readableFiles) {
                System.out.println("Sending file " + file.getName() + " " + file.getUid() + " to client " + req.getUsername());
                buildPullReply(reply, file, req.getUsername());

            }
            reply.setOk(true);
            responseObserver.onNext(reply.build());
            responseObserver.onCompleted();
        }

        private void buildPullReply(PullReply.Builder reply, File file, String username) {
            FileVersion mostRecentVersion = fileVersionRepository.getMostRecentVersion(file.getUid());
            byte[] file_bytes = new byte[0];
            try {
                file_bytes = Files.readAllBytes(
                        Paths.get(SIRS_DIR + "/src/assets/serverFiles/" + file.getUid()));
            } catch (IOException e) {
                e.printStackTrace();
            }
            reply.addVersionUids(mostRecentVersion.getVersionUid());
            reply.addFileUids(file.getUid());
            reply.addFilenames(file.getName());
            reply.addOwners(file.getOwner());
            reply.addIvs(ByteString.copyFrom(file.getIv()));
            reply.addPartIds(file.getPartition());
            reply.addFiles(ByteString.copyFrom(
                    file_bytes));
            reply.addPublicKeys(ByteString.copyFrom(fileRepository.getFileOwnerPublicKey(mostRecentVersion.getVersionUid())));
            reply.addDigitalSignatures(ByteString.copyFrom(mostRecentVersion.getDigitalSignature()));
            reply.addAESEncrypted(ByteString.copyFrom(getAESEncrypted(username, file.getUid(), "read")));
        }

        @Override
        public void pullSelected(PullSelectedRequest req, StreamObserver<PullReply> responseObserver) {

            System.out.println();
            System.out.println("Pull Selected request received");

            PullReply.Builder reply = PullReply.newBuilder();
            List<File> readableFiles = this.fileRepository.getUserReadableFiles(req.getUsername());
            for (int i = 0; i < req.getFilenamesCount(); i++) {
                for (File file : readableFiles) {
                    if (req.getFilenames(i).equals(file.getName())) {
                        System.out.println("Sending file " + file.getName() + " to client " + req.getUsername());
                        buildPullReply(reply, file, req.getUsername());
                        break;
                    }
                }
            }
            reply.setOk(true);
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

            System.out.println();
            System.out.println("Received a give permission request");

            GivePermissionReply reply = null;

            if (allUsernamesExist(req.getOthersNamesList())) {
                if (filenameExists(req.getUid())) {
                    giveUsersPermission(req.getOthersNamesList(), req.getUid(), req.getMode(), req.getOtherAESEncryptedList().stream().map(ByteString::toByteArray).collect(Collectors.toList()));
                    reply = GivePermissionReply.newBuilder().setOkOthers(true).setOkUid(true).build();
                }
            } else
                reply = GivePermissionReply.newBuilder().setOkOthers(false).setOkUid(false).build();

            System.out.println("Granting permission to requested users for file " + req.getUid());
            responseObserver.onNext(reply);
            responseObserver.onCompleted();
        }

        @Override
        public void getAESEncrypted(GetAESEncryptedRequest req, StreamObserver<GetAESEncryptedReply> responseObserver) {
            GetAESEncryptedReply.Builder replyBuilder;
            boolean owner = false;
            if (isOwner(req.getUsername(), req.getUid())) {
                owner = true;
            }
            byte[] aes = getAESEncrypted(req.getUsername(), req.getUid(), req.getMode());
            List<byte[]> pk = userRepository.getPublicKeysByUsernames(req.getOthersNamesList());
            byte[] iv = fileRepository.getFileIv(req.getUid());
            replyBuilder = GetAESEncryptedReply
                    .newBuilder()
                    .setIsOwner(owner)
                    .addAllOthersPublicKeys(
                            pk.stream()
                                    .map(ByteString::copyFrom)
                                    .collect(Collectors.toList())
                    )
                    .setIv(ByteString.copyFrom(iv));
            if (aes != null) {
                replyBuilder.setAESEncrypted(ByteString.copyFrom(aes));
            }
            GetAESEncryptedReply reply = replyBuilder.build();


            responseObserver.onNext(reply);
            responseObserver.onCompleted();
        }

        @Override
        public void verifyPassword(VerifyPasswordRequest req, StreamObserver<VerifyPasswordReply> responseObserver) {
            VerifyPasswordReply reply;
            if (isCorrectPassword(req.getUsername(), req.getPassword().toByteArray())) {
                reply = VerifyPasswordReply.newBuilder().setOkPassword(true).build();
            } else {
                reply = VerifyPasswordReply.newBuilder().setOkPassword(false).build();
            }

            responseObserver.onNext(reply);
            responseObserver.onCompleted();
        }

        public void replicateFile(String partId, ByteString file, String versionId) throws SSLException {
            List<String> servers = getZooPaths("/sirs/ransomware/backups");
            for (String server : servers) {
                String pair = server.split("/")[4];
                String part = pair.split("_")[0];
                String id = pair.split("_")[1];
                if (part.equals(partId)) {
                    System.out.println("Sending backup to server " + id);
                    backupFile(server, file, versionId);
                }

            }
        }

        public List<String> getZooPaths(String zooPath) {
            ArrayList<ZKRecord> recs = null;
            try {
                recs = new ArrayList<>(zkNaming.listRecords(zooPath));
            } catch (ZKNamingException e) {
                e.printStackTrace();
            }

            assert recs != null;
            return recs.stream().map(ZKRecord::getPath).collect(Collectors.toList());
        }

        public ByteString getBackup(String zooPath, String uid) throws SSLException {
            ZKRecord record = null;
            ByteString bytes;
            BackupServerGrpc.BackupServerBlockingStub blockingStub;
            ManagedChannel channel;
            try {
                record = zkNaming.lookup(zooPath);
            } catch (ZKNamingException e) {
                e.printStackTrace();
            }
            assert record != null;
            System.out.println(record.getURI());
            channel = NettyChannelBuilder.forTarget(record.getURI())
                    .overrideAuthority("foo.test.google.fr")  /* Only for using provided test certs. */
                    .sslContext(buildSslContext(trustCertCollection, certChain, privateKey))
                    .build();
            blockingStub = BackupServerGrpc.newBlockingStub(channel);
            bytes = blockingStub.getBackup(
                    GetBackupRequest
                            .newBuilder()
                            .setUid(uid)
                            .build()
            ).getFile();

            channel.shutdown();

            return bytes;
        }

        public void backupFile(String zooPath, ByteString file, String uid) throws SSLException {
            ZKRecord record = null;
            BackupServerGrpc.BackupServerBlockingStub blockingStub;
            ManagedChannel channel;
            try {
                record = zkNaming.lookup(zooPath);
            } catch (ZKNamingException e) {
                e.printStackTrace();
            }
            assert record != null;

            channel = NettyChannelBuilder.forTarget(record.getURI())
                    .overrideAuthority("foo.test.google.fr")  /* Only for using provided test certs. */
                    .sslContext(buildSslContext(trustCertCollection, certChain, privateKey))
                    .build();

            blockingStub = BackupServerGrpc.newBlockingStub(channel);
            BackupFileReply reply = blockingStub.backupFile(
                    BackupFileRequest
                            .newBuilder()
                            .setFile(file)
                            .setUid(uid)
                            .build()
            );

            if (reply.getOk())
                System.out.println("Backup version stored in backupServer");
            else
                System.out.println("Backup version failed to store");

            channel.shutdown();

        }


        private boolean isCorrectPassword(String username, byte[] password) {

            byte[] userSecret = userRepository.getUserPassword(username);
            return (Arrays.equals(password, userSecret));

        }

        private void registerUser(String name, byte[] password, byte[] salt, byte[] publicKeyBytes) {
            User user = new User(name, password, salt, ITERATIONS, publicKeyBytes);
            user.saveInDatabase(this.c);
        }

        private void registerFile(String uid, String filename, String owner, String partId, byte[] AESEncrypted, byte[] iv) {
            server.domain.file.File file = new server.domain.file.File(uid, owner, filename, partId, AESEncrypted, iv);
            file.saveInDatabase(this.c);
        }

        private void registerFileVersion(String versionId, String fileId, String creator, byte[] digitalSignature) {
            FileVersion fileVersion = new FileVersion(versionId, fileId, creator, new Date(System.currentTimeMillis()), digitalSignature);
            fileVersion.saveInDatabase(this.c);
        }

        private boolean usernameExists(String name) {
            User user = userRepository.getUserByUsername(name);
            return user.getUsername() != null && user.getPassHash() != null && user.getSalt() != null;
        }

        private boolean allUsernamesExist(List<String> names) {
            boolean bool = true;
            for (String name : names) {
                User user = userRepository.getUserByUsername(name);
                if (user.getUsername() == null || user.getPassHash() == null || user.getSalt() == null || user.getPublicKey() == null) {
                    bool = false;
                }
            }
            return bool;

        }

        private boolean filenameExists(String uid) {
            File file = fileRepository.getFileByUID(uid);
            return file.getUid() != null && file.getName() != null && file.getPartition() != null && file.getOwner() != null;
        }

        private void giveUsersPermission(List<String> usernames, String uid, String mode, List<byte[]> AESEncrypted) {
            for (int i = 0; i < usernames.size(); i++) {
                userRepository.setUserPermissionFile(usernames.get(i), uid, mode, AESEncrypted.get(i));
            }
        }

        private byte[] getAESEncrypted(String username, String uid, String mode) {
            return fileRepository.getAESEncrypted(username, uid, mode);
        }

        private boolean isOwner(String username, String uid) {
            return userRepository.isOwner(username, uid);
        }

    }
}
