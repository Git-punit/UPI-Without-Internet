// Creates demo users demo-alice / demo-bob (password: demo-password), a device each, and two payments
// (one succeeds, one fails for insufficient funds) against a running backend. Local demo data only.
// Run from the repo root after `mvn install`:  java -cp protocol/target/classes scripts/SeedDemo.java
import com.upioffline.protocol.*;
import java.net.URI; import java.net.http.*; import java.security.*; import java.time.Duration; import java.util.*;
public class SeedDemo {
  static HttpClient http = HttpClient.newHttpClient(); static String base = "http://localhost:8081/api/v1";
  static String call(String m, String p, String body, String token) throws Exception {
    var b = HttpRequest.newBuilder(URI.create(base + p)).header("Content-Type","application/json");
    if (token != null) b.header("Authorization","Bearer "+token);
    var r = http.send(b.method(m, body==null?HttpRequest.BodyPublishers.noBody():HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
    System.out.println(m+" "+p+" -> "+r.statusCode()+" "+r.body()); return r.body(); }
  static String field(String json, String k){ int i=json.indexOf("\""+k+"\":\"")+k.length()+4; return json.substring(i, json.indexOf('"', i)); }
  static String login(String u) throws Exception { String c="{\"username\":\""+u+"\",\"password\":\"demo-password\"}"; call("POST","/auth/register",c,null); return field(call("POST","/auth/login",c,null),"token"); }
  static KeyPair device(String tok, String user, String id) throws Exception {
    var g=KeyPairGenerator.getInstance("RSA"); g.initialize(2048); var kp=g.generateKeyPair();
    String proof=Base64.getEncoder().encodeToString(EnvelopeCrypto.sign(EnvelopeCrypto.registrationMessage(id,user),kp.getPrivate()));
    call("POST","/devices/register","{\"deviceId\":\""+id+"\",\"publicKey\":\""+EnvelopeCrypto.publicKeyToBase64(kp.getPublic())+"\",\"proof\":\""+proof+"\"}",tok); return kp; }
  public static void main(String[] a) throws Exception {
    String at=login("demo-alice"), bt=login("demo-bob");
    var ak=device(at,"demo-alice","alice-phone"); device(bt,"demo-bob","bob-phone");
    PublicKey bk=EnvelopeCrypto.publicKeyFromBase64(field(call("GET","/keys/backend",null,null),"publicKey"));
    for (long amt: new long[]{250_00, 900_00}) {
      Envelope e=EnvelopeCrypto.seal(PaymentInstruction.create("alice-phone","bob-phone",amt,"INR",Duration.ofHours(1)),ak.getPrivate(),bk);
      call("POST","/transactions","{\"protocolVersion\":1,\"transactionId\":\""+e.transactionId()+"\",\"senderId\":\""+e.senderId()+"\",\"receiverId\":\""+e.receiverId()+"\",\"nonce\":\""+e.nonce()+"\",\"encryptedKey\":\""+e.encryptedKey()+"\",\"ciphertext\":\""+e.ciphertext()+"\"}",bt);
    }
  }
}
