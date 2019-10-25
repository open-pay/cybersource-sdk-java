package com.cybersource.ws.client;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Properties;

import javax.security.auth.login.CredentialException;

import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.ext.WSSecurityException;

/**
 * Created by jeaton on 3/11/2016.
 */
public class MessageHandlerKeyStore extends Merlin {

    Logger logger = null;
    
	public MessageHandlerKeyStore(Logger logger) throws CredentialException, IOException, WSSecurityException {
        super(null, null, null);
        properties = new Properties();
        this.logger = logger;
    }

    public void addIdentityToKeyStore(Identity id) throws SignEncryptException {
        if (id == null)
            return;
        X509Certificate certificate = id.getX509Cert();
        PrivateKey privateKey = id.getPrivateKey();
        try {
            if (privateKey != null) {
                X509Certificate[] certChain = {certificate};
                getKeyStore().setKeyEntry(id.getKeyAlias(), privateKey, id.getPswd(), certChain);
            } else {
                getKeyStore().setCertificateEntry(id.getKeyAlias(), certificate);
            }
        } catch (KeyStoreException e) {
        	logger.log(Logger.LT_EXCEPTION, "MessageHandlerKeyStore cannot parse identity, " + id + "'");
            throw new SignEncryptException("MessageHandlerKeyStore, " +
                    "cannot parse identity, " + id + "'", e);
        }
    }

}
