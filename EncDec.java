package tus_crypto;
import java.nio.charset.StandardCharsets;
//import java.security.Provider;
//import java.security.Security;
import java.security.*;
//import java.security.SecureRandom;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;


class EncDec {
// Setting constant for algorithm value for use throughout Class	
String ALGORITHM = "AES";	

	//public static void main(String[] args) {
		void listAlgos() {
		    // Get the list of providers
		    Provider[] providers = Security.getProviders();

		    // Iterate over each provider
		    for (Provider provider : providers) {
		        System.out.println("Provider: " + provider.getName());
		        // Get the set of services (algorithms) provided by this provider
		        Set<Provider.Service> services = provider.getServices();
		        // Iterate over each service
		        for (Provider.Service service : services) {
		            // Check if this service is for KeyGenerator and printout
		            if (service.getType().equals("KeyGenerator")) {
		                System.out.println("\tKeyGeneration Algorithm: " + service.getAlgorithm());
		            }
		      // Print all algorithms and their type  
		                System.out.println(service.getType()+   " " + service.getAlgorithm());
		                }
		           }
		}
		
		byte[] encryptData(String plainText, SecretKey sharedKey) {
			String ciphertextString;
			byte[] encText =null;
			try {
				Cipher encCipher = Cipher.getInstance(ALGORITHM);
				encCipher.init(Cipher.ENCRYPT_MODE, sharedKey);
				byte[] plainTextBytes = plainText.getBytes();
				encText = encCipher.doFinal(plainTextBytes);
				ciphertextString = new String(encText, StandardCharsets.UTF_8);
				//System.out.println(ciphertextString);
			}
			catch(Exception e){
				System.out.println("error encrypting data.");
			}
			return encText;
		}

		String decryptData(byte[] cipherText, SecretKey sharedKey) {
			String cleartextString;
			
			try {
				Cipher decCipher = Cipher.getInstance(ALGORITHM);
				decCipher.init(Cipher.DECRYPT_MODE, sharedKey);
				//byte[] cipherTextBytes = cipherText;
				byte[] decText = decCipher.doFinal(cipherText);
				cleartextString = new String(decText, StandardCharsets.UTF_8);
				//System.out.println(cleartextString);
			}
			catch(Exception e){
				cleartextString = "error decrypting data.";
			}
			return cleartextString;
		}
		
}