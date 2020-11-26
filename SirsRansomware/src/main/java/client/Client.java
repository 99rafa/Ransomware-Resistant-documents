package client;

import PBKDF2.PBKDF2Main;
import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NettyChannelBuilder;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.apache.commons.io.FileUtils;
import proto.*;
import pt.ulisboa.tecnico.sdis.zk.ZKNaming;
import pt.ulisboa.tecnico.sdis.zk.ZKNamingException;
import pt.ulisboa.tecnico.sdis.zk.ZKRecord;
import server.Server;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ssl.SSLException;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A simple client that requests a greeting from the {@link Server} with TLS.
 */
public class Client {
    private final static int ITERATIONS = 10000;
    private static final int INDEX_PATH = 0;
    private static final int INDEX_UID = 1;
    private static final int INDEX_PART_ID = 2;
    private static final int INDEX_NAME = 3;
    private static final Logger logger = Logger.getLogger(Client.class.getName());
    private static final String SIRS_DIR = System.getProperty("user.dir");
    private static final String FILE_MAPPING_PATH = SIRS_DIR + "/src/assets/data/fm.txt";
    private static final String PULLS_DIR = SIRS_DIR + "/src/assets/clientPulls/";

    private final ManagedChannel channel;
    private final ServerGrpc.ServerBlockingStub blockingStub;
    private String username = null;
    private byte[] salt = null;

    /**
     * Construct client connecting to HelloWorld server at {@code host:port}.
     */
    public Client(String zooHost,
                  String zooPort,
                  SslContext sslContext) {

        Random random = new Random();
        String path;
        System.out.println(zooHost + ":" + zooPort);
        ZKNaming zkNaming = new ZKNaming(zooHost, zooPort);
        ArrayList<ZKRecord> recs = null;
        try {
            recs = new ArrayList<>(zkNaming.listRecords("/sirs/ransomware/servers"));
        } catch (ZKNamingException e) {
            e.printStackTrace();
        }


        assert recs != null;
        path = recs.get(random.nextInt(recs.size())).getPath();
        ZKRecord record = null;
        try {
            record = zkNaming.lookup(path);
        } catch (ZKNamingException e) {
            e.printStackTrace();
        }


        assert record != null;
        this.channel = NettyChannelBuilder.forTarget(record.getURI())
                .overrideAuthority("foo.test.google.fr")  /* Only for using provided test certs. */
                .sslContext(sslContext)
                .build();
        blockingStub = ServerGrpc.newBlockingStub(channel);
    }

    private static SslContext buildSslContext(String trustCertCollectionFilePath,
                                              String clientCertChainFilePath,
                                              String clientPrivateKeyFilePath) throws SSLException {
        SslContextBuilder builder = GrpcSslContexts.forClient();
        if (trustCertCollectionFilePath != null) {
            builder.trustManager(new File(trustCertCollectionFilePath));
        }
        if (clientCertChainFilePath != null && clientPrivateKeyFilePath != null) {
            builder.keyManager(new File(clientCertChainFilePath), new File(clientPrivateKeyFilePath));
        }
        return builder.build();
    }

    /**
     * Greet server. If provided, the first element of {@code args} is the name to use in the
     * greeting.
     */
    public static void main(String[] args) throws Exception {
        if (args.length != 5) {
            System.out.println("USAGE: host port trustCertCollectionFilePath " +
                    "clientCertChainFilePath clientPrivateKeyFilePath");
            System.exit(0);
        }

        /* Use default CA. Only for real server certificates. */
        Client client = new Client(args[0], args[1],
                buildSslContext(args[2], args[3], args[4]));

        try {
            Scanner in = new Scanner(System.in);
            boolean running = true;
            while (running) {
                String cmd = in.nextLine();
                switch (cmd) {
                    case "greet" -> client.greet(in.nextLine());
                    case "login" -> client.login();
                    case "register" -> client.register();
                    case "help" -> client.displayHelp();
                    case "pull" -> client.pull();
                    case "give_perm" -> client.givePermission();
                    case "push" -> client.push();
                    case "logout" -> client.logout();
                    case "exit" -> running = false;
                    default -> System.out.println("Command not recognized");
                }
            }
        } finally {
            client.shutdown();
        }
    }

    public void shutdown() throws InterruptedException {
        channel.shutdown().awaitTermination(5, TimeUnit.SECONDS);
    }

    /**
     * Say hello to server.
     */
    public void register() {

        Console console = System.console();
        String name = console.readLine("Enter a username: ");

        boolean match = false;
        String passwd = "";

        while (!match) {
            passwd = new String(console.readPassword("Enter a password: "));
            String confirmation = new String(console.readPassword("Confirm your password: "));
            if (passwd.equals(confirmation))
                match = true;
            else System.out.println("Password don't match. Try again");
        }
        byte[] salt = PBKDF2Main.getNextSalt();
        System.out.println("Will try to register " + name + " ...");
        // generate RSA Keys
        KeyPair keyPair = generateUserKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Get the bytes of the public and private keys
        byte[] privateKeyBytes = privateKey.getEncoded(); //keep privatekey in Keystore
        byte[] publicKeyBytes = publicKey.getEncoded();

        RegisterRequest request = RegisterRequest.newBuilder()
                .setUsername(name)
                .setPassword(ByteString.copyFrom(generateSecurePassword(passwd,salt)))
                .setSalt(ByteString.copyFrom(salt))
                .setPublicKey(ByteString.copyFrom(publicKeyBytes))
                .build();
        RegisterReply response;
        try {
            response = blockingStub.register(request);
        } catch (StatusRuntimeException e) {
            logger.log(Level.WARNING, "RPC failed: {0}", e.getStatus());
            return;
        }
        logger.info("User registered successfully");
        System.out.println(response.getOk());
        //this.username = name;
    }



    public void login() {
        int tries = 0;
        Console console = System.console();

        while (tries < 3) {

            String name = console.readLine("Enter your username: ");
            String password = new String(console.readPassword("Enter your password: "));
            //Save user salt
            SaltRequest req = SaltRequest.newBuilder().setUsername(name).build();
            byte[] salt = blockingStub.salt(req).getSalt().toByteArray();
            LoginRequest request = LoginRequest.newBuilder()
                    .setUsername(name)
                    .setPassword(ByteString.copyFrom(generateSecurePassword(password, salt)))
                    .build();

            LoginReply response;

            try {
                response = blockingStub.login(request);
            } catch (StatusRuntimeException e) {
                logger.log(Level.WARNING, "RPC failed: {0}", e.getStatus());
                return;
            }
            if (response.getOkUsername()) {
                if (response.getOkPassword()) {
                    this.username = name;
                    this.salt = salt;
                    System.out.println("Successful Authentication. Welcome " + name + "!");
                    break;
                } else {
                    tries++;
                    System.err.println("Wrong password.Try again");
                }
            } else {
                System.err.println("Username is too long or does not exist. Try again");
            }
        }

        if (tries == 3) {
            System.err.println("Exceeded the number of tries. Client logged out.");
            logout();
        }
    }

    public void logout() {

        this.username = null;
    }

    private byte[] generateSecurePassword(String password, byte[] salt) {
        byte[] key = null;
        try {
            char[] chars = password.toCharArray();
            //rafa edit: this is just to demonstrate how to generate a PBKDF2 password-based kdf
            // because the salt needs to be the same
            //byte[] salt = PBKDF2Main.getNextSalt();

            PBEKeySpec spec = new PBEKeySpec(chars, salt, Client.ITERATIONS, 256 * 8);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            key = skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return key;
    }

    /**
     * Say hello to server.
     */
    public void greet(String name) {
        System.out.println("Will try to greet " + name + " ...");
        HelloRequest request = HelloRequest.newBuilder().setName(name).build();
        HelloReply response;
        try {
            response = blockingStub.sayHello(request);
        } catch (StatusRuntimeException e) {
            logger.log(Level.WARNING, "RPC failed: {0}", e.getStatus());
            return;
        }
        System.out.println("Greeting: " + response.getMessage());
    }

    public Map<String, String> getUidMap(int index1, int index2) throws FileNotFoundException {
        Map<String, String> fileMapping = new TreeMap<>();
        try {
            new FileOutputStream(FILE_MAPPING_PATH, true).close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        Scanner sc = new Scanner(new File(FILE_MAPPING_PATH));

        while (sc.hasNextLine()) {
            String[] s = sc.nextLine().split(" ");
            String path = s[index1];
            String uid = s[index2];
            fileMapping.put(path, uid);
        }
        return fileMapping;
    }

    public void appendTextToFile(String text, String filePath) {
        try {
            BufferedWriter writer;
            writer = new BufferedWriter(
                    new FileWriter(filePath, true));
            writer.write(text);
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public String generateFileUid(String filePath, String partId, String name) throws IOException {
        if (!getUidMap(INDEX_PATH, INDEX_UID).containsKey(filePath)) {
            String uid = UUID.randomUUID().toString();
            String textToAppend = filePath + " " + uid + " " + partId + " " + name + "\n";

            appendTextToFile(textToAppend, FILE_MAPPING_PATH);

            return uid;
        } else return getUidMap(INDEX_PATH, INDEX_UID).get(filePath);
    }

    public String getUid(String filename) throws FileNotFoundException {
        Scanner sc = new Scanner(new File(FILE_MAPPING_PATH));
        while (sc.hasNextLine()) {
            String[] s = sc.nextLine().split(" ");
            if (s[INDEX_NAME].equals(filename))
                return s[INDEX_UID];

        }
        return null;
    }

    public byte[] createDigitalSignature(byte[] fileBytes, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        //Creating a Signature object
        Signature sign = Signature.getInstance("SHA256withDSA");

        //Initialize the signature
        sign.initSign(privateKey);

        //Adding data to the signature
        sign.update(fileBytes);
        //Calculating the signature

        return sign.sign();
    }

    public boolean verifyDigitalSignature(byte[] signature, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        //Creating a Signature object
        Signature sign = Signature.getInstance("SHA256withDSA");
        //Initializing the signature

        sign.initVerify(publicKey);
        sign.update(signature);

        //Verifying the signature
        return sign.verify(signature);
    }

    public void push() {
        if (username != null) {
            try {
                Scanner input = new Scanner(System.in);
                System.out.print("File path: ");
                String filePath = input.nextLine();
                boolean isNew = !getUidMap(INDEX_PATH, INDEX_UID).containsKey(filePath);
                File f = new File(filePath);
                if (!f.exists()) {
                    System.out.println("No such file");
                    return;
                }
                byte[] file_bytes = Files.readAllBytes(
                        Paths.get(filePath)
                );
                //TODO PICK RANDOM PARTITION
                //TODO STATIC FOR NOW
                String partId = "1";
                String filename;
                if (isNew) {
                    System.out.print("Filename: ");
                    filename = input.nextLine();
                } else
                    filename = getUidMap(INDEX_PATH, INDEX_NAME).get(filePath);
                String uid = generateFileUid(filePath, partId, filename);

                //TODO
                //bytes[] digitalSignature = createDigitalSignature(file_bytes, getPrivateKey() );
                int tries = 0;

                while (tries < 3) {
                    String passwd = new String((System.console()).readPassword("Enter a password: "));
                    System.out.println("Sending file to server");
                    PushReply res;
                    PushRequest req;
                    generateSecureFile();
                    req = PushRequest
                            .newBuilder()
                            .setFile(
                                    ByteString.copyFrom(
                                            file_bytes))
                            .setUsername(this.username)
                            //TODO
                            //.setDigitalSignature(digitalSignature)
                            .setPassword(ByteString.copyFrom(generateSecurePassword(passwd, this.salt)))
                            .setFileName(filename)
                            .setUid(uid)
                            .setPartId(partId)
                            .build();
                    res = blockingStub.push(req);
                    if (res.getOk()) {
                        System.out.println("File uploaded successfully");
                        break;
                    } else {
                        System.err.println("Wrong password!");
                        tries++;
                    }
                }
                if (tries == 3) {
                    System.err.println("Exceeded the number of tries. Client logged out.");
                    logout();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else System.err.println("Error: To push a file, you need to login first");
    }

    public void displayHelp() {
        System.out.println("greet - sends greet to server");
        System.out.println("login - logins on file server");
        System.out.println("register - registers on file server server");
        System.out.println("help - displays help message");
        System.out.println("pull - receives files from server");
        System.out.println("push - sends file to server");
        System.out.println("give_perm - give read/write file access permission to a user");
        System.out.println("logout - exits client");
        System.out.println("exit - exits client");
    }

    public void pull() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        if (username == null) {
            System.err.println("Error: To pull files, you need to login first");
            return;
        }
        String choice = ((System.console().readLine("Select which files you want to pull, separated by a blank space. 'all' for pulling every file: ")));


        Map<String, String> uidMap = getUidMap(INDEX_UID, INDEX_PATH);
        String passwd = new String((System.console()).readPassword("Enter a password: "));

        PullReply reply;
        if (choice.equals("all")) {
            PullAllRequest request = PullAllRequest
                    .newBuilder()
                    .setUsername(this.username)
                    .setPassword(ByteString.copyFrom(generateSecurePassword(passwd, this.salt)))
                    .build();
            reply = blockingStub.pullAll(request);
        } else {
            String[] fileNames = choice.split(" ");
            List<String> uids = new ArrayList<>();
            for (String file : fileNames) {

                if (getUid(file) != null)
                    uids.add(getUid(file));
                else
                    System.err.println("Error: file " + file + " does not exist in the database. File ignored.");
            }
            PullSelectedRequest request = PullSelectedRequest
                    .newBuilder()
                    .setUsername(this.username)
                    .setPassword(ByteString.copyFrom(generateSecurePassword(passwd, this.salt)))
                    .addAllUids(uids)
                    .build();
            reply = blockingStub.pullSelected(request);
        }


        if (!reply.getOk())
            System.err.println("Wrong password!");
        else {
            for (int i = 0; i < reply.getFilenamesCount(); i++) {
                System.out.println("Received file " + reply.getFilenames(i));
                String uid = reply.getUids(i);
                String filename = reply.getFilenames(i);
                String owner = reply.getOwners(i);
                String partId = reply.getPartIds(i);
                byte[] file_data = reply.getFiles(i).toByteArray();
                byte[] digitalSignature = reply.getDigitalSignatures(i).toByteArray();

                //VERIFY FILE DATA
                //GET FILE OWNER PUBLIC KEY
                byte[] ownerPublicKey = blockingStub.getFileOwnerPublicKey(
                        GetFileOwnerPublicKeyRequest
                                .newBuilder()
                                .setUid(uid)
                                .build()
                ).getPublicKey().toByteArray();

                X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(ownerPublicKey);
                KeyFactory kf = KeyFactory.getInstance("RSA");

                PublicKey pk = kf.generatePublic(X509publicKey);
                //VERIFY SIGNATURE
                if(!verifyDigitalSignature(digitalSignature,pk))
                    System.out.println("TA MAU DE SAL");
                    //TODO RETRIEVE HEALTHY VERSION
                else
                    System.out.println("TA BOM DE SAL");

                //IF FILE EXISTS OVERWRITE IT
                if (uidMap.containsKey(uid))
                    FileUtils.writeByteArrayToFile(new File(uidMap.get(uid)), file_data);
                    //ELSE CREATE IT
                else {
                    FileUtils.writeByteArrayToFile(new File(PULLS_DIR + filename), file_data);
                    String text = PULLS_DIR + filename + " " + uid + " " + partId + " " + filename;
                    appendTextToFile(text, FILE_MAPPING_PATH);
                }

            }
        }
    }

    public void givePermission() {
        Console console = System.console();
        String other = console.readLine("Enter the username to give permission: ");
        String s = ((System.console().readLine("Select what type of permission:\n -> 'read' for read permission\n -> 'write' for read/write permission\n")));
        String filename = console.readLine("Enter the filename: ");
        String uid = null;



        try {
            uid = getUid(filename);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        GetAESEncryptedRequest req = GetAESEncryptedRequest
                .newBuilder()
                .setUsername(this.username)
                .setOther(other)
                .setUid(uid)
                .build();
        GetAESEncryptedReply reply = blockingStub.getAESEncrypted(req);
        byte[] aesEncrypted= reply.getAESEncrypted().toByteArray();
        if(reply.getIsOwner()){
            //desencriptar com a privada, encriptar com a publica do outro e mandar para o server



            //read/write permissions
            GivePermissionRequest request = GivePermissionRequest
                    .newBuilder()
                    .setUsername(other)
                    .setUid(uid)
                    .setMode(s)
                    .build();
            GivePermissionReply res = blockingStub.givePermission(request);

            if (res.getOkMode()) {
                if (res.getOkUsername()) {
                    if (res.getOkUid()) {
                        switch (s) {
                            case "read" -> System.out.println("Read permission of file " + filename + " granted for user " + username);
                            case "write" -> System.out.println("Write permission of file " + filename + " granted for user " + username);
                        }
                    }
                } else System.out.println("Username do not exist");
            } else System.out.println("Wrong type of permission inserted");

        }else System.out.println("You are not the owner of this file, you cannot give permission");

    }

    public void generateSecureFile() {

    }
    private KeyPair generateUserKeyPair() {
        KeyPair keyPair = null;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            keyGen.initialize(2048, random);
            keyPair = keyGen.genKeyPair();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return keyPair;
    }

}