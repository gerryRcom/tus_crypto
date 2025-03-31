package tus_crypto;

import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Client {

   public static void main(String[] args) throws Exception {
	   
	   // open socket and streams for use throughout communications
	   InetAddress inet = InetAddress.getByName("localhost");
	   Socket s = new Socket(inet, 2000);
	   ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
	   ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
  
	   System.out.println("Client: Running...");
	   System.out.println("Client: Configuring Shared Key");
	   SecretKey sharedKey = clientSharedKey(oos, ois);
	   System.out.println("Client: Secret Key generated: "+sharedKey.hashCode());
	   System.out.println("Client: ################################");
	   System.out.println("Client: Begining client/ server authentication");
	   clientAuthenticate(sharedKey, oos, ois);
      
      
   }
  
   
	// Function to generate shared key with server using DH key exchange
	static SecretKey clientSharedKey(ObjectOutputStream oos, ObjectInputStream ois) throws Exception{
		
	      // get DH params as string
	      String params = generateParams();
	      
	      // send DH params as string
	      System.out.println("Client: Sending DH Parameters to Server");
	      oos.writeObject(params);
	      
	      // create DHParameterSpec object
	      // Retrieve DH Parameters from generateParams method.
	      String[] values = params.split(",");
	      BigInteger clientPrime = new BigInteger(values[0]);
	      BigInteger clientGen = new BigInteger(values[1]);
	      int clientSize = Integer.parseInt(values[2]);
	      DHParameterSpec dhClientSpec = new DHParameterSpec(clientPrime, clientGen, clientSize);
	      
	      // Generate a DH key pair (using DHParameterSpec object)
	      KeyPairGenerator clientKeyGen = KeyPairGenerator.getInstance("DH");
	      clientKeyGen.initialize(dhClientSpec);
	      KeyPair clientKeyPair = clientKeyGen.generateKeyPair();
	      PrivateKey clientPrivateKey = clientKeyPair.getPrivate();
	      PublicKey clientPublicKey = clientKeyPair.getPublic();
	    
	      // send own public key using oos.
	      System.out.println("Client: Sending Public Key: "+clientPublicKey);
	      oos.writeObject(clientPublicKey);
	    
	      // read servers public key using ois. and Downcast to PublicKey
	      PublicKey serverPublicKey = (PublicKey) ois.readObject();
	      System.out.println("Client: Receiving Server's Public Key: "+serverPublicKey);
	      // close socket
	      //s.close();

	      // generate symmetric key
	      KeyAgreement ka = KeyAgreement.getInstance("DH");
	      ka.init(clientPrivateKey);
	      ka.doPhase(serverPublicKey, true);
	      byte[] rawValue = ka.generateSecret();
	      SecretKey secretKey = new SecretKeySpec(rawValue, 0, 16, "AES");

	      // return key
	      return secretKey;
		
	}

   public static String generateParams() {

      String s = null;
      try {
         // Create the parameter generator for a 1024-bit DH key pair
         AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
         paramGen.init(1024);

         // Generate the parameters
         AlgorithmParameters params = paramGen.generateParameters();
         DHParameterSpec dhSpec = (DHParameterSpec) params.getParameterSpec(DHParameterSpec.class);
         s = dhSpec.getP() + "," + dhSpec.getG() + "," + dhSpec.getL();

      } catch (Exception e) {
         e.printStackTrace();
      }
      return s;
   }

	static void clientAuthenticate(SecretKey sharedKey, ObjectOutputStream oos, ObjectInputStream ois) throws Exception {
		// hmac message for use during authentication
		String hmacMessage = "dcsdcjdnjcccscsCSECCESCEcescee";
	      
	      // send hmac message as string
	      System.out.println("Client: Sending HMAC message to server: "+hmacMessage);
	      oos.writeObject(hmacMessage);
			
	      Mac clientMac = Mac.getInstance("HmacSHA256");
	      clientMac.init(sharedKey);
	      byte[] clientHmacSignature = clientMac.doFinal(hmacMessage.getBytes());
	      System.out.println("Client: Sending HMAC signature to server: "+clientHmacSignature);
	      oos.writeObject(clientHmacSignature);
	
	}
	

}