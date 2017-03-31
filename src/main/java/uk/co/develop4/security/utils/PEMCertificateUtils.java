/* 
 * =============================================================================
 * 
 *  Copyright (c) 2014, The Develop4 Technologies Ltd (http://www.develop4.co.uk)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * =============================================================================
 */
package uk.co.develop4.security.utils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Logger;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;

import uk.co.develop4.security.ConfigurationException;

public final class PEMCertificateUtils {

	private final static Logger logger = Logger.getLogger(PEMCertificateUtils.class.getName());

	public static PublicKey getPublicKey(String fileName, String passphrase, String providerName) {
		KeyPair keyPair = null;
		try {
			keyPair = getKeyPairFromOpenSslPemFile(fileName, passphrase, providerName);
			return keyPair.getPublic();
		} catch (ConfigurationException ex1) {
			logger.warning("Failed to load Public Key, probably due to incorrect password: " + ex1.getMessage());
			ex1.printStackTrace();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}
	
	public static PrivateKey getPrivateKey(String fileName, String passphrase, String providerName) {
		KeyPair keyPair = null;
		try { 
			keyPair = getKeyPairFromOpenSslPemFile(fileName, passphrase, providerName);
			return keyPair.getPrivate();
		} catch (ConfigurationException ex1) {
			logger.warning("Failed to load Private Key, probably due to incorrect password: " + ex1.getMessage());
		} catch (Exception ex2) {
			ex2.printStackTrace();
		}
		return null;
	}

	private static KeyPair getKeyPairFromOpenSslPemFile(String fileName, String passphrase, String providerName) throws IOException, ConfigurationException {
		Reader fRd = null;
        PEMParser pemParser = null;
        KeyPair keypair = null;
        try {
	        JcaPEMKeyConverter   converter = new JcaPEMKeyConverter().setProvider(providerName);
	        File file = IOCodecUtils.isFile(fileName);
	        FileReader fr = new FileReader(file);			
            fRd = new BufferedReader(fr);
            pemParser = new PEMParser(fRd);
	        Object obj = pemParser.readObject();
	        if (obj instanceof PEMEncryptedKeyPair) {
		        PEMDecryptorProvider pemProv = new JcePEMDecryptorProviderBuilder().setProvider(providerName).build(passphrase.toCharArray());
	        	keypair = converter.getKeyPair(((PEMEncryptedKeyPair)obj).decryptKeyPair(pemProv));
	        } else if (obj instanceof PKCS8EncryptedPrivateKeyInfo) {
		        InputDecryptorProvider pkcs8Prov = new JceOpenSSLPKCS8DecryptorProviderBuilder().build(passphrase.toCharArray());
		        keypair = new KeyPair(null, converter.getPrivateKey(((PKCS8EncryptedPrivateKeyInfo)obj).decryptPrivateKeyInfo(pkcs8Prov)));
	        } else if (obj instanceof SubjectPublicKeyInfo) {
	        	keypair = new KeyPair((PublicKey)converter.getPublicKey((SubjectPublicKeyInfo)obj),null);
	        } else if (obj instanceof X509CertificateHolder) {
	        	SubjectPublicKeyInfo sub = (SubjectPublicKeyInfo)((X509CertificateHolder)obj).getSubjectPublicKeyInfo();
	        	keypair = new KeyPair((PublicKey)converter.getPublicKey((SubjectPublicKeyInfo)sub),null);
	        } else {
	        	keypair = converter.getKeyPair((PEMKeyPair)obj);
	        }
        } catch (Exception ex) {
        	throw new ConfigurationException(ex.getCause());
        } finally {
        	pemParser.close();
        }
        return keypair;
	}	
}
