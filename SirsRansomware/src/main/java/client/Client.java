package client;

import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NettyChannelBuilder;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import proto.*;
import pt.ulisboa.tecnico.sdis.zk.ZKNaming;
import pt.ulisboa.tecnico.sdis.zk.ZKNamingException;
import pt.ulisboa.tecnico.sdis.zk.ZKRecord;
import server.Server;

import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLException;

/**
 * A simple client that requests a greeting from the {@link Server} with TLS.
 */
public class Client {
    private static final Logger logger = Logger.getLogger(Client.class.getName());
    private static final String FILE_MAPPING_PATH = "/Users/rafael/Documents/IST/MEIC/SIRS/project/SIRS_proj1/SirsRansomware/src/assets/data/fm.txt";

    private final ManagedChannel channel;
    private final ServerGrpc.ServerBlockingStub blockingStub;
    private String username = "";

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
     * Construct client connecting to HelloWorld server at {@code host:port}.
     */
    public Client(String zooHost,
                  String zooPort,
                  SslContext sslContext) {

        Random random = new Random();
        String path;
        System.out.println( zooHost+ ":" + zooPort);
        ZKNaming zkNaming = new ZKNaming(zooHost, zooPort);
        ArrayList<ZKRecord> recs = null;
        try {
            recs = new ArrayList<>(zkNaming.listRecords("/sirs/ransomware/servers"));
        } catch (ZKNamingException e) {
            e.printStackTrace();
        }


        path = recs.get(random.nextInt(recs.size())).getPath();
        ZKRecord record = null;
        try {
            record = zkNaming.lookup(path);
        } catch (ZKNamingException e) {
            e.printStackTrace();
        }


        this.channel = NettyChannelBuilder.forTarget(record.getURI())
                .overrideAuthority("foo.test.google.fr")  /* Only for using provided test certs. */
                .sslContext(sslContext)
                .build();
        blockingStub = ServerGrpc.newBlockingStub(channel);
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

        while (! match) {
            passwd = new String(console.readPassword("Enter a password: " ));
            String confirmation = new String(console.readPassword("Confirm your password: " ));
            if (passwd.equals(confirmation))
                match = true;
            else System.out.println("Password don't match. Try again");
        }
        System.out.println(passwd);
        logger.info("Will try to register " + name + " ...");
        RegisterRequest request = RegisterRequest.newBuilder().setUsername(name).setPassword(passwd).build();
        RegisterReply response;
        try {
            response = blockingStub.register(request);
        } catch (StatusRuntimeException e) {
            logger.log(Level.WARNING, "RPC failed: {0}", e.getStatus());
            return;
        }
        logger.info("User registered successfully" );
        System.out.println(response.getOk());
        this.username = name;
    }

    /**
     * Say hello to server.
     */
    public void greet(String name) {
        logger.info("Will try to greet " + name + " ...");
        HelloRequest request = HelloRequest.newBuilder().setName(name).build();
        HelloReply response;
        try {
            response = blockingStub.sayHello(request);
        } catch (StatusRuntimeException e) {
            logger.log(Level.WARNING, "RPC failed: {0}", e.getStatus());
            return;
        }
        logger.info("Greeting: " + response.getMessage());
    }


    public Map<String,String> getUidMap() throws FileNotFoundException {
        Map<String,String> fileMapping = new TreeMap<>();
        Scanner sc = new Scanner(new File(FILE_MAPPING_PATH));
        while (sc.hasNextLine()){
            String[] s = sc.nextLine().split(" ");
            String path = s[0];
            String uid = s[1];
            fileMapping.put(path,uid);
        }
        return fileMapping;
    }

    public String generateFileUid(String filePath) throws IOException {
        if(!getUidMap().containsKey(filePath)) {
            String uid = UUID.randomUUID().toString();
            String textToAppend = filePath + " " + uid + "\n";

            //Set true for append mode
            BufferedWriter writer = new BufferedWriter(
                    new FileWriter(FILE_MAPPING_PATH, true));

            writer.write(textToAppend);
            writer.close();
            return uid;
        }
        else return getUidMap().get(filePath);
    }

    public void push(){
        try {
            Scanner input = new Scanner(System.in);
            System.out.print("File path: ");
            String filePath = input.nextLine();
            boolean isNew = !getUidMap().containsKey(filePath);
            File f = new File(filePath);
            if(!f.exists()){
                System.out.println("No such file");
                return;
            }
            byte[] file_bytes = Files.readAllBytes(
                    Paths.get(filePath)
            );
            String uid = generateFileUid(filePath);
            String filename = "";
            if(isNew){
                System.out.print("Filename: ");
                filename = input.nextLine();
            }
            int tries = 0;

            while (tries < 3) {
                String passwd = new String((System.console()).readPassword("Enter a password: "));
                logger.info("Sending file to server");
                PushReply res;
                PushRequest req;
                req = PushRequest
                        .newBuilder()
                        .setFile(
                                ByteString.copyFrom(
                                        file_bytes))
                        .setUsername(this.username)
                        .setPassword(passwd)
                        .setFileName(filename)
                        .setUid(uid)
                        .build();
                res = blockingStub.push(req);
                if (res.getOk()) {
                    logger.info("File uploaded successfully");
                    break;
                }
                else {
                    logger.info("Wrong password!");
                    tries++;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void displayHelp(){
        System.out.println("greet - sends greet to server");
        System.out.println("login - logins on file server");
        System.out.println("register - registers on file server server");
        System.out.println("help - displays help message");
        System.out.println("pull - recieves files from server");
        System.out.println("push - sends file to server");
        System.out.println("exit - exits client");
    }

    /**
     * Greet server. If provided, the first element of {@code args} is the name to use in the
     * greeting.
     */
    public static void main(String[] args) throws Exception {
        if (args.length < 2 || args.length == 4 || args.length > 5) {
            System.out.println("USAGE: HelloWorldClientTls host port file_path [trustCertCollectionFilePath " +
                    "[clientCertChainFilePath clientPrivateKeyFilePath]]\n  Note: clientCertChainFilePath and " +
                    "clientPrivateKeyFilePath are only needed if mutual auth is desired.");
            System.exit(0);
        }

        /* Use default CA. Only for real server certificates. */
        Client client = switch (args.length) {
            case 2 -> new Client(args[0], args[1],
                    buildSslContext(null, null, null));
            case 3 -> new Client(args[0], args[1],
                    buildSslContext(args[2], null, null));
            default -> new Client(args[0], args[1],
                    buildSslContext(args[2], args[3], args[4]));
        };

        try {
            Scanner in = new Scanner(System.in);
            boolean running = true;
            while(running){
                String cmd = in.nextLine();
                switch (cmd) {
                    case "greet" -> client.greet(in.nextLine());
                    case "login" -> System.out.println("login");
                    case "register" -> client.register();
                    case "help" -> client.displayHelp();
                    case "pull" -> System.out.println("pull");
                    case "push" -> client.push();
                    case "exit" -> running = false;
                    default -> System.out.println("Command not recognized");
                }
            }
        } finally {
            client.shutdown();
        }
    }

    static class ClientImp extends ClientGrpc.ClientImplBase {}

}