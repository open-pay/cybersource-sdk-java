package com.cybersource.ws.client;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Enumeration;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.message.WSSecEncrypt;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;


/**
 * Created by jeaton on 3/1/2016.
 */
public class SignedAndEncryptedMessageHandler extends BaseMessageHandler {

    private static final String KEY_FILE_TYPE = "PKCS12";
    
    //public static List<Identity> identities = new ArrayList<Identity>()
    private static ConcurrentHashMap<String, Identity> identities = new ConcurrentHashMap<String, Identity>();
    
	private static String currentMerchantId = null;
	
    private static final String SERVER_ALIAS = "CyberSource_SJC_US";
    
    // By default signature algorithm is set to null and during WSSecSignature build() Signature algorithm will set to "http://www.w3.org/2000/09/xmldsig#rsa-sha1" .
    public static final String SIGNATURE_ALGORITHM = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    // By default digest algorithm is set to "http://www.w3.org/2000/09/xmldsig#sha1"
    public static final String DIGEST_ALGORITHM = "http://www.w3.org/2001/04/xmlenc#sha256";
    
	// This is loaded by WSS4J but since we use it lets make sure its here
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    private SignedAndEncryptedMessageHandler(MerchantConfig merchantConfig, Logger logger) throws SignEncryptException, SignException {
        super(logger);
         // load keystore from disk p12 file (not keystore)
        loadMerchantP12File(merchantConfig, logger);
        for (String key : identities.keySet()) {
            localKeyStoreHandler.addIdentityToKeyStore(identities.get(key));
        }
    }

    static SignedAndEncryptedMessageHandler getInstance(MerchantConfig merchantConfig, Logger logger)
            throws SignEncryptException, SignException {
        SignedAndEncryptedMessageHandler signedAndEncryptedMessageHandler = new SignedAndEncryptedMessageHandler(merchantConfig,logger);
        return signedAndEncryptedMessageHandler;
    }
    
    /**
    * Method loads the Merchant P12 key.
    *  IMPORTANT :This change is made based on the assumptions that at point of time , a merchant will have only one P12 Key 
    * @param merchantConfig - Merchant Config 
    * @param logger - logger instance
    * @throws SignException - Signature exception
    */
    private static void loadMerchantP12File(MerchantConfig merchantConfig, Logger logger) throws SignException {
        // Load the KeyStore and get the signing key and certificate do this once only
        // This change is made based on the assumptions that at point of time , a merchant will have only one P12 Key
        if (!merchantConfig.getMerchantID().equals(currentMerchantId)) {
            readAndStoreCertificateAndPrivateKey(merchantConfig, logger);
        }
    }
   
   /**
	 *Reads the Certificate or Public key  and Private from the P12 key .
    * @param merchantConfig - Merchant Config details
    * @param logger - logger object
    * @throws SignException
    */
   
    private static void readAndStoreCertificateAndPrivateKey(
			MerchantConfig merchantConfig, Logger logger) throws SignException {
    	KeyStore merchantKeyStore;
        try {
            merchantKeyStore = KeyStore.getInstance(KEY_FILE_TYPE,
                    new BouncyCastleProvider());
        } catch (KeyStoreException e) {
            logger.log(Logger.LT_EXCEPTION, "Exception while instantiating KeyStore");
            throw new SignException(e);
        }
		
        File tempFile = null;
        FileInputStream stream = null;
        try {
            if(merchantConfig.getKeySupplier() != null){
                tempFile = merchantConfig.getKeySupplier().getFile(merchantConfig.getKeyFilename());
                if(tempFile == null){
                    merchantKeyStore.load(new FileInputStream(merchantConfig.getKeyFile()), merchantConfig.getKeyPassword().toCharArray());
                }else{
                    stream = new FileInputStream(tempFile);
                    merchantKeyStore.load(stream, merchantConfig.getKeyPassword().toCharArray());
                    merchantConfig.getLastModifiedFiles().put(merchantConfig.getKeyFilename(), tempFile.lastModified());
                }
            } else {
                merchantKeyStore.load(new FileInputStream(merchantConfig.getKeyFile()), merchantConfig.getKeyPassword().toCharArray());
            }
        } catch (IOException e) {
            logger.log(Logger.LT_EXCEPTION, "Exception while loading KeyStore, '" + merchantConfig.getKeyFilename() + "'");
            throw new SignException(e);
        } catch (NoSuchAlgorithmException e) {
            logger.log(Logger.LT_EXCEPTION, "Exception while loading KeyStore, '" + merchantConfig.getKeyFilename() + "'");
            throw new SignException(e);
        } catch (CertificateException e) {
            logger.log(Logger.LT_EXCEPTION, "Exception while loading KeyStore, '" + merchantConfig.getKeyFilename() + "'");
            throw new SignException(e);
        } catch (ConfigException e) {
            logger.log(Logger.LT_EXCEPTION, "Exception while loading KeyStore, '" + merchantConfig.getKeyFilename() + "'");
            throw new SignException(e);
        }finally{
            if(stream != null){
                try {
                    stream.close();
                } catch (IOException e) {
                    // Ignore
                }
            }
            if(tempFile != null && merchantConfig.getKeySupplier().isTemporary()){
                tempFile.deleteOnExit();
                tempFile.delete();
            }
        }
        
     // our p12 files do not contain an alias as a normal name, its the common name and serial number
        String merchantKeyAlias = null;
        try {
            Enumeration enumKeyStore = merchantKeyStore.aliases();
            while (enumKeyStore.hasMoreElements()) {
            	KeyStore.PrivateKeyEntry keyEntry = null;
            	merchantKeyAlias = (String) enumKeyStore.nextElement();
				if (merchantKeyAlias.contains(merchantConfig.getKeyAlias())){
            		try {
            			keyEntry = (KeyStore.PrivateKeyEntry) merchantKeyStore.getEntry
                                (merchantKeyAlias, new KeyStore.PasswordProtection(merchantConfig.getKeyPassword().toCharArray()));
                    } catch (NoSuchAlgorithmException e) {
                        logger.log(Logger.LT_EXCEPTION, "Exception while obtaining private key from KeyStore with alias, '" + merchantConfig.getKeyAlias() + "'");
                        throw new SignException(e);
                    } catch (UnrecoverableEntryException e) {
                        logger.log(Logger.LT_EXCEPTION, "Exception while obtaining private key from KeyStore with alias, '" + merchantConfig.getKeyAlias() + "'");
                        throw new SignException(e);
                    } catch (KeyStoreException e) {
                        logger.log(Logger.LT_EXCEPTION, "Exception while obtaining private key from KeyStore with alias, '" + merchantConfig.getKeyAlias() + "'");
                        throw new SignException(e);
                    }
            		Identity identity = new Identity(merchantConfig,(X509Certificate) keyEntry.getCertificate(),keyEntry.getPrivateKey(), logger);
            		identities.put(identity.getName(), identity);
            		continue;
            	}
				Identity identity = new Identity(merchantConfig, (X509Certificate) merchantKeyStore.getCertificate(merchantKeyAlias), logger); 
				identities.put(identity.getName(), identity);
            }
            
            if (identities == null || identities.isEmpty()) {
                logger.log(Logger.LT_EXCEPTION, "No valid entries found in the KeyStore, check alias, '" + merchantConfig.getKeyAlias() + "'");
                throw new SignException("No valid entries found in the KeyStore, check alias, '" + merchantConfig.getKeyAlias() + "'");
            }
            currentMerchantId = merchantConfig.getMerchantID();
        } catch (KeyStoreException e) {
            logger.log(Logger.LT_EXCEPTION, "Exception while obtaining private key from KeyStore with alias, '" + merchantConfig.getKeyAlias() + "'");
            throw new SignException(e);
        }
	}
    
    public Document handleMessageCreation(Document workingDocument, String senderAlias,String password) throws SignEncryptException, SignException{
        if (senderAlias == null)
            throw new SignEncryptException("SignedAndEncryptedMessageHandler - handleMessageCreation," +
                    " senderAlias is null");

	    WSSecHeader secHeader = new WSSecHeader(workingDocument);
	    try {
	      secHeader.insertSecurityHeader();
	    } catch (WSSecurityException e) {
	        logger.log(Logger.LT_EXCEPTION, "Exception while adding docuemnt in soap securiy header for MLE");
	        throw new SignException(e);
	    }

        WSSecEncrypt encrBuilder = new WSSecEncrypt();
        //Set the user name to get the encryption certificate. 
        //The public key of this certificate is used, thus no password necessary. The user name is a keystore alias usually.
        encrBuilder.setUserInfo(SERVER_ALIAS);
        
        /*This is to reference a public key or certificate when signing or encrypting a SOAP message.
        *The following valid values for these configuration items are:
		*IssuerSerial (default),DirectReference[BST],X509KeyIdentifier,Thumbprint,SKIKeyIdentifier,KeyValue (signature only),EncryptedKeySHA1 (encryption only)
        */
        encrBuilder.setKeyIdentifierType(WSConstants.X509_KEY_IDENTIFIER);
        
        //This encryption algorithm is used to encrypt the data. 
        encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_256);
        
        //Sets the algorithm to encode the symmetric key. Default is the WSConstants.KEYTRANSPORT_RSAOEP algorithm.
        //encrBuilder.setKeyEnc(WSConstants.KEYTRANSPORT_RSAOEP);

        
        //Create signed document
        Document signedDoc = createSignedDoc(workingDocument,senderAlias,password,secHeader);

        Document signedEncryptedDoc;
		try {
			//Builds the SOAP envelope with encrypted Body and adds encrypted key.
	        // If no external key (symmetricalKey) was set ,generate an encryption
	        // key (session key) for this Encrypt element. This key will be
	        // encrypted using the public key of the receiver
			signedEncryptedDoc = encrBuilder.build(signedDoc, localKeyStoreHandler, secHeader);
		} catch (WSSecurityException e) {
			logger.log(Logger.LT_EXCEPTION, "Failed while encrypting signed requeest for , '" + senderAlias + "'" + " with " + SERVER_ALIAS);
			throw new SignEncryptException(e.getMessage(), e);
		}
        encrBuilder.prependToHeader(secHeader);
        return signedEncryptedDoc;
    }
	
	public Document createSignedDoc(Document workingDocument,String senderAlias, String password,WSSecHeader secHeader) throws SignException {
		
		if(secHeader==null){
			try {
        	secHeader = new WSSecHeader(workingDocument);
        	secHeader.insertSecurityHeader();
			} catch (WSSecurityException e) {
	            logger.log(Logger.LT_EXCEPTION, "Exception while signing XML document");
	            throw new SignException(e);
	        }
    	}
		WSSecSignature sign = new WSSecSignature();
		sign.setUserInfo(identities.get(senderAlias).getKeyAlias(), password);
		sign.setDigestAlgo(DIGEST_ALGORITHM);
	    sign.setSignatureAlgorithm(SIGNATURE_ALGORITHM);
	    sign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
	    sign.setUseSingleCertificate(true);
	    
	    //Set which parts of the message to encrypt/sign.
	    WSEncryptionPart msgBodyPart = new WSEncryptionPart(WSConstants.ELEM_BODY, WSConstants.URI_SOAP11_ENV, "");
        sign.getParts().addAll(Collections.singletonList(msgBodyPart));
		try {
	        return sign.build(workingDocument, localKeyStoreHandler, secHeader);
		} catch (WSSecurityException e) {
	        logger.log(Logger.LT_EXCEPTION, "Failed while signing request for , '" + senderAlias + "'");
	        throw new SignException(e.getMessage());
	   }
	}
}
