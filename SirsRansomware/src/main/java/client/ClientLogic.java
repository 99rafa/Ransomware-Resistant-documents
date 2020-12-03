package client;

import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import proto.*;
import server.Server;

import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * A simple client that requests a greeting from the {@link Server} with TLS.
 */
public class ClientLogic {
    private ServerGrpc.ServerBlockingStub blockingStub;
    private ManagedChannel channel;


    /**
     * Construct client connecting to HelloWorld server at {@code host:port}.
     */
    public ClientLogic(ServerGrpc.ServerBlockingStub blockingStub, ManagedChannel channel) {
        this.blockingStub = blockingStub;
        this.channel = channel;
    }

    public GivePermissionReply GivePermission(String[] othersNames, String uid, String s, List<byte[]> othersAesEncrypted) {
        return blockingStub.givePermission(GivePermissionRequest
                .newBuilder()
                .addAllOthersNames(Arrays.asList(othersNames))
                .setUid(uid)
                .setMode(s)
                .addAllOtherAESEncrypted(othersAesEncrypted.stream().map(ByteString::copyFrom).collect(Collectors.toList()))
                .build());
    }

    public GetAESEncryptedReply GetAESEncrypted(String username, String[] othersNames, String uid) {
        return blockingStub.getAESEncrypted(GetAESEncryptedRequest
                .newBuilder()
                .setUsername(username)
                .addAllOthersNames(Arrays.asList(othersNames))
                .setUid(uid)
                .build());
    }

    public GetAESEncryptedReply GetAESEncrypted(String username, String name, String uid) {
        return blockingStub.getAESEncrypted(GetAESEncryptedRequest
                .newBuilder()
                .setUsername(username)
                .addAllOthersNames(Collections.singleton(name))
                .setUid(uid)
                .build());
    }

    public VerifyPasswordReply VerifyPassword(String username, byte[] passwd) {
        return blockingStub.verifyPassword(VerifyPasswordRequest
                .newBuilder()
                .setUsername(username)
                .setPassword(ByteString.copyFrom(passwd))
                .build());
    }

    public UsernameExistsReply UsernameExists(String username){
        return blockingStub.usernameExists(UsernameExistsRequest
                .newBuilder()
                .setUsername(username)
                .build());
    }

    public PullReply PullAll(String username) {
        return blockingStub.pullAll(PullAllRequest
                .newBuilder()
                .setUsername(username)
                .build());

    }

    public PullReply PullSelected(String username, String[] fileNames) {
        return blockingStub.pullSelected(PullSelectedRequest
                .newBuilder()
                .setUsername(username)
                .addAllFilenames(Arrays.asList(fileNames))
                .build());
    }

    public HealCorruptedVersionReply HealCorruptedVersion(String version_uid, String file_uid, byte[] healthyVersion, String partId) {
        return blockingStub.healCorruptedVersion(HealCorruptedVersionRequest
                .newBuilder()
                .setVersionUid(version_uid)
                .setFileUid(file_uid)
                .setFile(ByteString.copyFrom(healthyVersion))
                .setPartId(partId)
                .build());

    }

    public RevertMostRecentVersionReply RevertMostRecentVersion(String file_uid, String version_uid) {
        return blockingStub.revertMostRecentVersion(
                RevertMostRecentVersionRequest
                        .newBuilder()
                        .setFileUid(file_uid)
                        .setVersionUid(version_uid)
                        .build());
    }

    public RetrieveHealthyVersionsReply RetrieveHealthyVersions(String version_uid) {
        return blockingStub.retrieveHealthyVersions(
                RetrieveHealthyVersionsRequest
                        .newBuilder()
                        .setUid(version_uid)
                        .build());
    }

    public ListFileVersionsReply ListFileVersions(String fileUid) {
        return blockingStub.listFileVersions(
                ListFileVersionsRequest
                        .newBuilder()
                        .setFileUid(fileUid)
                        .build());
    }

    public PushReply Push(byte[] iv, byte[] file, byte[] encryptedAES, String username, byte[] digitalSignature, String filename, String uid, String partId) {
        return blockingStub.push(PushRequest
                .newBuilder()
                .setIv(ByteString.copyFrom(iv))
                .setFile(ByteString.copyFrom(file))
                .setAESEncrypted(ByteString.copyFrom(encryptedAES))
                .setUsername(username)
                .setDigitalSignature(ByteString.copyFrom(digitalSignature))
                .setFileName(filename)
                .setUid(uid)
                .setPartId(partId)
                .build());
    }

    public GetPublicKeysByUsernamesReply GetPublicKeysByUsernames(String username) {
        return blockingStub.getPublicKeysByUsernames(GetPublicKeysByUsernamesRequest
                .newBuilder()
                .addAllUsernames(Collections.singleton(username))
                .build());
    }

    public HelloReply Hello(String name) {
        return blockingStub.sayHello(HelloRequest
                .newBuilder()
                .setName(name)
                .build());
    }

    public RegisterReply Register(String name, byte[] passwd,byte[] publicKeyBytes,byte[] salt) {
        return blockingStub.register(RegisterRequest.newBuilder()
                .setUsername(name)
                .setPassword(ByteString.copyFrom(passwd))
                .setSalt(ByteString.copyFrom(salt))
                .setPublicKey(ByteString.copyFrom(publicKeyBytes))
                .build());
    }

    public SaltReply Salt(String name){
        return blockingStub.salt(SaltRequest
                .newBuilder()
                .setUsername(name)
                .build());
    }


    public void Shutdown() throws InterruptedException {
        channel.shutdown().awaitTermination(5, TimeUnit.SECONDS);
    }

}
