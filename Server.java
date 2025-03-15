package tus_crypto;

import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Server {

	public static void main(String[] args) throws Exception {



			SecretKey sharedKey = serverSharedKey();
			serverAuthenticate(sharedKey);
			
		    
			//Declare EncDec object for shared key decryption later.
			//EncDec encDecObject = new EncDec();
			//Uncomment if you want to view list of algorithms
			//encDecObject.listAlgos();
			//byte[] test1 = encDecObject.encryptData("hide me", sharedKey);
			//System.out.println(encDecObject.decryptData(test1, sharedKey));

		}
	
	// Function to generate shared key with client using DH key exchange
	static SecretKey serverSharedKey() throws Exception{
		
			Socket s;
			ServerSocket ss = new ServerSocket(2000);
			while (true) {
				System.out.println("Server: waiting for key exchange ..");
				// Socket
				s = ss.accept();
				ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
				ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
		
				// Read DH params as string
				String dhParams = (String) ois.readObject();
				// create DHParameterSpec object
				String[] values = dhParams.split(",");
				BigInteger serverPrime = new BigInteger(values[0]);
				BigInteger serverGen = new BigInteger(values[1]);
				int serverSize = Integer.parseInt(values[2]);
					
				// Complete creation of DHParameterSpec object from data above
				DHParameterSpec dhServerSpec = new DHParameterSpec(serverPrime, serverGen, serverSize);

				// generate own DH key pair (using DHParameterSpec object)
				KeyPairGenerator serverKeyGen = KeyPairGenerator.getInstance("DH");
				serverKeyGen.initialize(dhServerSpec);
				KeyPair serverKeyPair = serverKeyGen.generateKeyPair();
				PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
				PublicKey serverPublicKey = serverKeyPair.getPublic();
				      
				// read client public key using ois. and Downcast to PublicKey
				PublicKey clientPublicKey = (PublicKey) ois.readObject();

				// send own public key
				oos.writeObject(serverPublicKey);

				// generate symmetric key
			    KeyAgreement ka = KeyAgreement.getInstance("DH");
			    ka.init(serverPrivateKey);
			    ka.doPhase(clientPublicKey, true);
			    byte[] rawValue = ka.generateSecret();
			    SecretKey secretKey = new SecretKeySpec(rawValue, 0, 16, "AES");

				// Base64 encode the Secret key and print it out,  Un-comment to view server's key to compare with clients
			    // String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
			    // System.out.println("Server encoded key: " + encodedKey);
				return secretKey;
			}
	}

	static void serverAuthenticate(SecretKey sharedKey) throws Exception {
		//String hmacMessage = "dcsdcjdnjcccscsCSECCESCEcescee";

	
		Socket s;
		ServerSocket ss = new ServerSocket(2001);
		while (true) {
			System.out.println("Server: waiting for client Authentication ..");
			// Socket
			s = ss.accept();
			ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
			ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
			
			String hmacMessage = (String) ois.readObject();
			System.out.println("Received HMAC Message "+ hmacMessage);
			
			Mac serverMac = Mac.getInstance("HmacSHA256");
			serverMac.init(sharedKey);
			byte[] serverHmacSignature = serverMac.doFinal(hmacMessage.getBytes());
			
			byte[] clientHmacSignature = (byte[]) ois.readObject();
			
			if (serverHmacSignature == clientHmacSignature){
				System.out.println("Client Authenticated");
			}
			//String hmac1 = Base64.getEncoder().encodeToString(serverHmacSignature);
			//String hmac2 = Base64.getEncoder().encodeToString(clientHmacSignature);
			//System.out.println(hmac1);
			//System.out.println(hmac2);
			
			
	}
	}
}