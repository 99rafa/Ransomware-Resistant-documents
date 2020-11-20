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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Scanner;
import java.util.ArrayList;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLException;

/**
 * A simple client that requests a greeting from the {@link Server} with TLS.
 */
public class Client {
    private static final Logger logger = Logger.getLogger(Client.class.getName());

    private final ManagedChannel channel;
    private final ServerGrpc.ServerBlockingStub blockingStub;

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

        System.out.println("OLA");
        Random random = new Random();
        String path;
        System.out.println( zooHost+ ":" + zooPort);
        ZKNaming zkNaming = new ZKNaming(zooHost, zooPort);
        ArrayList<ZKRecord> recs = null;
        System.out.println("OLA");
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

        System.out.println("OLA");
        
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

    public void fileTransfer(String filename){
        try {
            System.out.print("Password: ");
            Scanner input = new Scanner(System.in);
            String passwd = input.nextLine();
            logger.info("Sending file to server");
            FileTransferReply res;
            byte[] file_bytes = Files.readAllBytes(
                    Paths.get(filename)
            );
            FileTransferRequest req = FileTransferRequest
                    .newBuilder()
                    .setFile(
                            ByteString.copyFrom(
                                    file_bytes)).setPassword(passwd)
                    .build();
            res = blockingStub.fileTransfer(req);
            if(res.getOk())
                logger.info("File sent");
            else
                logger.info("File failed to send");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Greet server. If provided, the first element of {@code args} is the name to use in the
     * greeting.
     */
    public static void main(String[] args) throws Exception {
        System.out.println("OLA");
        if (args.length < 3 || args.length == 5 || args.length > 6) {
            System.out.println("USAGE: HelloWorldClientTls host port file_path [trustCertCollectionFilePath " +
                    "[clientCertChainFilePath clientPrivateKeyFilePath]]\n  Note: clientCertChainFilePath and " +
                    "clientPrivateKeyFilePath are only needed if mutual auth is desired.");
            System.exit(0);
        }

        /* Use default CA. Only for real server certificates. */
        Client client = switch (args.length) {
            case 3 -> new Client(args[0], args[1],
                    buildSslContext(null, null, null));
            case 4 -> new Client(args[0], args[1],
                    buildSslContext(args[3], null, null));
            default -> new Client(args[0], args[1],
                    buildSslContext(args[3], args[4], args[5]));
        };

        try {
            client.greet("AFONSO");
            client.fileTransfer(args[2]);
        } finally {
            client.shutdown();
        }
    }

    static class ClientImp extends ClientGrpc.ClientImplBase {}

}