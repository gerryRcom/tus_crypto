package tus_crypto;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Server {

	public static void main(String[] args) throws Exception {

		// open socket and streams for use throughout communications
		System.out.println("============== Server: Key Exchange ==============");
		System.out.println("Server: waiting for key exchange ..");
		ServerSocket ss = new ServerSocket(2000);
		Socket s = ss.accept();
		ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
		ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
		

		SecretKey sharedKey = serverSharedKey(oos, ois);
		System.out.println("Server: Secret Key generated: "+sharedKey.hashCode());
		System.out.println("============== Server: Authentication ==============");
			
		if(serverAuthenticate(sharedKey,oos, ois)) {
			System.out.println("Client= and server sucessfully authenticated.");
			System.out.println("========== Server: Object Transmission ============");
			receiveObject(sharedKey, ois);
		}
		else {
			System.out.println("Client and server not authenticated, exiting.");
		}
			

		}
	
	// Function to generate shared key with client using DH key exchange
	static SecretKey serverSharedKey(ObjectOutputStream oos, ObjectInputStream ois) throws Exception{
		
			while (true) {	
				// Read DH params as string
				System.out.println("Server: Receiving DH Parameters from Client");
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
				System.out.println("Server: Receiving Client's public key: "+clientPublicKey.hashCode());
				

				// send own public key
				oos.writeObject(serverPublicKey);
				System.out.println("Server: Sending Public Key: "+serverPublicKey.hashCode());

				// generate symmetric key
			    KeyAgreement ka = KeyAgreement.getInstance("DH");
			    ka.init(serverPrivateKey);
			    ka.doPhase(clientPublicKey, true);
			    byte[] rawValue = ka.generateSecret();
			    SecretKey secretKey = new SecretKeySpec(rawValue, 0, 16, "AES");

			    // Return key
				return secretKey;
			}
	}

	static boolean serverAuthenticate(SecretKey sharedKey, ObjectOutputStream oos, ObjectInputStream ois) throws Exception {

		while (true) {
			System.out.println("Server: waiting for client Authentication ..");
			
			String hmacMessage = (String) ois.readObject();
			System.out.println("Received HMAC Message "+ hmacMessage);
			
			Mac serverMac = Mac.getInstance("HmacSHA256");
			serverMac.init(sharedKey);
			byte[] serverHmacSignature = serverMac.doFinal(hmacMessage.getBytes());
			
			byte[] clientHmacSignature = (byte[]) ois.readObject();
			
			
			if (Arrays.equals(serverHmacSignature, clientHmacSignature)){
				return true;
			}
			else {
				return false;
			}
			
	}
	}
	
	static void receiveObject(SecretKey sharedKey, ObjectInputStream ois) {
	     String ALGORITHM = "AES";
	     try {
	    	 SealedObject objectReceived = (SealedObject) ois.readObject();
		     Cipher receivingCipher = Cipher.getInstance(ALGORITHM);
		     // Initialize the cipher for decryption with the secret key
		     receivingCipher.init(Cipher.DECRYPT_MODE, sharedKey);
		     // Decrypt the received object using the SealedObject class
		     Asset newAsset = (Asset) objectReceived.getObject(receivingCipher);
		     //SealedObject objectoToSend = new SealedObject(assetToSend, sendingCipher);
		     // Send the encrypted object (so) by writing it on the output stream oos
		     //oos.writeObject(objectoToSend);
		     System.out.println("Server: Asset object received from client: "+newAsset.toString());
	     }	
	     catch(Exception e){
				System.out.println("Server: Error receiving encrypted object.");
			}
	}
}