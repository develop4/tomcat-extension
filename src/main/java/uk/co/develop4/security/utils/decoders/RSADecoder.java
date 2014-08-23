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
package uk.co.develop4.security.utils.decoders;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.jasypt.encryption.StringEncryptor;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateCrtKey;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;

import uk.co.develop4.security.utils.PropertyNaming;

/**
 * 
 * TODO: rename the parameters to encrypt/decrypt key
 * TODO: pass the keys as strings to the init to allow embeding in web page
 * TODO: cache keys in local variables to prevent re-read operations
 * TODO: build individual unit tests, hand craft the strings in the tests and do not rely on file system.
 * 
 * @author william timpany
 *
 */
public class RSADecoder implements Decoder, StringEncryptor {

	private static org.apache.juli.logging.Log log = org.apache.juli.logging.LogFactory.getLog(RSADecoder.class);

	private static final String INFO 		= "RSA Decoder Test v1.00";
	private static final String CLASSNAME 	= RSADecoder.class.getName();
	private String NAMESPACE 				= "rsa://";
	private String DESCRIPTION 				= "RSA";
    
    
    private String DEFAULT_NAMESPACE 					= "rsa://";
    private String DEFAULT_PASSPHRASE 					= "446576656C6F7034546563686E6F6C6F67696573";
    private String DEFAULT_PROVIDER_NAME 				= "BC";
    private String DEFAULT_ALGORITHM_NAME 				= "RSA/None/PKCS1Padding";
    
    private String DEFAULT_PRIVATE_KEY_FILE 			= "private.pem";
    private String DEFAULT_PUBLIC_KEY_FILE 			= "public.pem";
        
    private String passphrase;
    private String providerName;
    private String algorithimName;
    private String privateKeyFile;
    private String publicKeyFile;
    
    private Properties properties;
    private boolean debug = false;
    
    public Map<String,Set<String>> getRequiredParameters() {
    	Map<String,Set<String>> requiredParams = new HashMap<String,Set<String>>();
    	Set<String> encodeParams = new HashSet<String>(Arrays.asList(
    			PropertyNaming.PROP_PASSPHRASE.toString(), 
    			PropertyNaming.PROP_PRIVATE_KEYFILE.toString()
    			)) ;
    	Set<String> decodeParams = new HashSet<String>(Arrays.asList(
    			PropertyNaming.PROP_PUBLIC_KEYFILE.toString()
    			)) ;
    	requiredParams.put("encode", encodeParams);
    	requiredParams.put("decode", decodeParams);
    	return requiredParams;
    }
    
    public Map<String,Set<String>> getOptionalParameters() {
    	Map<String,Set<String>> optionalParams = new HashMap<String,Set<String>>();
    	Set<String> encodeParams = new HashSet<String>(Arrays.asList(
    			PropertyNaming.PROP_PROVIDER_NAME.toString(), 
    			PropertyNaming.PROP_ALGORITHM_NAME.toString(),
    			PropertyNaming.PROP_DEBUG.toString()
    			)) ;
    	Set<String> decodeParams = new HashSet<String>(Arrays.asList(
    			PropertyNaming.PROP_PROVIDER_NAME.toString(), 
    			PropertyNaming.PROP_ALGORITHM_NAME.toString(),
    			PropertyNaming.PROP_DEBUG.toString()
    			)) ;
    	optionalParams.put("encode", encodeParams);
    	optionalParams.put("decode", decodeParams);
    	return optionalParams;
    }
    
	public RSADecoder() {
	}

	public String getNamespace() {
		return NAMESPACE;
	}
	
	public String getDescription() {
		return DESCRIPTION;
	}
	
	public void setNamespace(String namespace) {
		this.NAMESPACE = namespace;
	}
	
	public void setDescription(String description) {
		this.DESCRIPTION = description;
	}
	
	public String getInfo() {
		return INFO;
	}
	
	public void init(String passphrase, Properties props)  {
		if(props != null) {
			this.properties = props;
		}
		this.setDebug(Boolean.parseBoolean(properties.getProperty((PropertyNaming.PROP_DEBUG.toString()), "false")));
		if (isDebug()) {
			log.info("Debug mode has been activated:");
		}
		
		// -- do the stuff, allow overriding the passphrase
		this.setPassphrase(passphrase);
		if (this.properties.getProperty(PropertyNaming.PROP_PASSPHRASE.toString()) != null){
			this.setPassphrase(this.properties.getProperty(PropertyNaming.PROP_PASSPHRASE.toString(), DEFAULT_PASSPHRASE));
		}

		this.setNamespace(this.properties.getProperty(PropertyNaming.PROP_NAMESPACE.toString(), DEFAULT_NAMESPACE));
		this.setProviderName(this.properties.getProperty(PropertyNaming.PROP_PROVIDER_NAME.toString(), DEFAULT_PROVIDER_NAME));
		this.setAlgorithimName(this.properties.getProperty(PropertyNaming.PROP_ALGORITHM_NAME.toString(), DEFAULT_ALGORITHM_NAME));
		this.setPrivateKeyFile(this.properties.getProperty(PropertyNaming.PROP_PRIVATE_KEYFILE.toString(), DEFAULT_PRIVATE_KEY_FILE));
		this.setPublicKeyFile(this.properties.getProperty(PropertyNaming.PROP_PUBLIC_KEYFILE.toString(), DEFAULT_PUBLIC_KEY_FILE));
		
		if (!this.getNamespace().equalsIgnoreCase(DEFAULT_NAMESPACE)) {
			log.info("Namespace Override: Default: " + DEFAULT_NAMESPACE + " \t New: " + this.getNamespace());
		}
		if (isDebug()) {
			for (String myKey : this.properties.stringPropertyNames()) {
				log.info("Properties: key: \"" + myKey + "\" value: \"" + this.properties.getProperty(myKey) + "\"");
			}
		}
	}
	
	public String encrypt(String clearText) {
		String cypherText = clearText;
		if (clearText == null) {
			return null;
		}
		try {
			KeyPair privateKey = getKeyPairFromOpenSslPemFile(this.getPublicKeyFile(), this.getPassphrase());
			Cipher cipher = Cipher.getInstance(this.getAlgorithimName(),this.getProviderName());
		    cipher.init(Cipher.ENCRYPT_MODE, privateKey.getPublic());
		    byte[] cypherBytes = cipher.doFinal(clearText.getBytes());	    
			cypherText = this.getNamespace() + Hex.toHexString(cypherBytes);
		} catch (Exception ex) { 
			ex.printStackTrace(); 
		}
		return cypherText;
	}

	public String decrypt(String cyphertext){
		String plainText = cyphertext;
		try {
			if (cyphertext != null && cyphertext.startsWith(this.getNamespace())) {
				String stripped = cyphertext.replace(this.getNamespace(), "");				
				KeyPair privateKey = getKeyPairFromOpenSslPemFile(this.getPrivateKeyFile(), this.getPassphrase());
				Cipher cipher = Cipher.getInstance(this.getAlgorithimName(),this.getProviderName());
			    cipher.init(Cipher.DECRYPT_MODE, privateKey.getPrivate());
			    byte[] plainBytes =  cipher.doFinal(Hex.decode(stripped));			    
				plainText = new String(plainBytes);
			}
		} catch (Exception ex) { 
			ex.printStackTrace(); 
		}
		return plainText;	
	}
	
	private KeyPair getKeyPairFromOpenSslPemFile(String  fileName, String passphrase) throws IOException {
		InputStream res = null;
        Reader fRd = null;
        PEMParser pemParser = null;
        KeyPair keypair = null;
        try {
	        JcaPEMKeyConverter   converter = new JcaPEMKeyConverter().setProvider(this.getProviderName());
	        PEMDecryptorProvider pemProv = new JcePEMDecryptorProviderBuilder().setProvider(this.getProviderName()).build(passphrase.toCharArray());
	        InputDecryptorProvider pkcs8Prov = new JceOpenSSLPKCS8DecryptorProviderBuilder().build(passphrase.toCharArray());
	        //res = this.getClass().getResourceAsStream(fileName);
	        File file = DecoderUtils.isFile(fileName);
	        FileReader fr = new FileReader(file);			
            fRd = new BufferedReader(fr);
            pemParser = new PEMParser(fRd);
	        Object obj = pemParser.readObject();

	        if (obj instanceof PEMEncryptedKeyPair) {
	        	keypair = converter.getKeyPair(((PEMEncryptedKeyPair)obj).decryptKeyPair(pemProv));
	        } else if (obj instanceof PKCS8EncryptedPrivateKeyInfo) {
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
        	log.error("Failed to read Keyfile:" + fileName);
        	ex.printStackTrace();
        } finally {
        	pemParser.close();
        }
        return keypair;
	}	
	
	public boolean isDebug() {
		return debug;
	}

	public void setDebug(final boolean debug) {
		this.debug = debug;
	}
	
	public String getPassphrase() {
		return this.passphrase;
	}

	public void setPassphrase(String passphrase) {
		this.passphrase = passphrase;
	}

	public String getProviderName() {
		return this.providerName;
	}

	public void setProviderName(String providerName) {
		this.providerName = providerName;
	}

	public String getAlgorithimName() {
		return this.algorithimName;
	}

	public void setAlgorithimName(String algorithimName) {
		this.algorithimName = algorithimName;
	}

	public String getPrivateKeyFile() {
		return this.privateKeyFile;
	}

	public void setPrivateKeyFile(String privateKeyFile) {
		this.privateKeyFile = privateKeyFile;
	}

	public String getPublicKeyFile() {
		return this.publicKeyFile;
	}

	public void setPublicKeyFile(String publicKeyFile) {
		this.publicKeyFile = publicKeyFile;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("RSADecoder [Namespace:");
		builder.append(getNamespace());
		builder.append(", Description:");
		builder.append(getDescription());
		builder.append(", Info:");
		builder.append(getInfo());
		builder.append("]");
		return builder.toString();
	}


}
