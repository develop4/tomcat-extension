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
package uk.co.develop4.security.codecs;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import javax.crypto.Cipher;

import org.bouncycastle.util.encoders.Hex;
import org.jasypt.encryption.StringEncryptor;

import uk.co.develop4.security.ConfigurationException;
import uk.co.develop4.security.utils.PEMCertificateUtils;
import uk.co.develop4.security.utils.PropertyNaming;

/**
 * 
 * @author wtimpany
 *
 */
public class RSACodec extends BaseCodec implements Codec, StringEncryptor {
    
	private final String DEFAULT_DESCRIPTION 			= "RSA codec";
    private final String DEFAULT_NAMESPACE 				= "rsa://";
    private final String DEFAULT_PASSPHRASE 			= "446576656C6F7034546563686E6F6C6F67696573";
    private final String DEFAULT_PROVIDER_NAME 			= "BC";
    private final String DEFAULT_ALGORITHM_NAME 		= "RSA/None/PKCS1Padding";
    
    private final String DEFAULT_PRIVATE_KEY_FILE 		= "private.pem";
    private final String DEFAULT_PUBLIC_KEY_FILE 		= "public.pem";
        
    private String passphrase;
    private String providerName;
    private String algorithimName;
    private String privateKeyFile;
    private String publicKeyFile;
    
    private PrivateKey privateKey;
    private PublicKey publicKey;
        
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
    			PropertyNaming.PROP_DEBUG.toString(),
    			PropertyNaming.PROP_LOGGING.toString()
    			)) ;
    	Set<String> decodeParams = new HashSet<String>(Arrays.asList(
    			PropertyNaming.PROP_PROVIDER_NAME.toString(), 
    			PropertyNaming.PROP_ALGORITHM_NAME.toString(),
    			PropertyNaming.PROP_DEBUG.toString(),
    			PropertyNaming.PROP_LOGGING.toString()
    			)) ;
    	optionalParams.put("encode", encodeParams);
    	optionalParams.put("decode", decodeParams);
    	return optionalParams;
    }
    
	public RSACodec() {
	}
	
	@Override
	public void init(String passphrase, Properties props)  throws ConfigurationException {
		try {
			setLogging(Boolean.parseBoolean(props.getProperty(PropertyNaming.PROP_LOGGING.toString(), "false")));
			setDebug(Boolean.parseBoolean(props.getProperty((PropertyNaming.PROP_DEBUG.toString()), "false")));
			setSnoop(Boolean.parseBoolean(props.getProperty(PropertyNaming.PROP_SNOOP.toString(), "false")));
			
			// -- do the stuff, allow overriding the passphrase
			setPassphrase(passphrase);
			if (props.getProperty(PropertyNaming.PROP_PASSPHRASE.toString()) != null){
				setPassphrase(props.getProperty(PropertyNaming.PROP_PASSPHRASE.toString(), DEFAULT_PASSPHRASE));
			}
	
			setNamespace(props.getProperty(PropertyNaming.PROP_NAMESPACE.toString(), DEFAULT_NAMESPACE));
			setDescription(props.getProperty(PropertyNaming.PROP_DESCRIPTION.toString(), DEFAULT_DESCRIPTION));	
	
			setProviderName(props.getProperty(PropertyNaming.PROP_PROVIDER_NAME.toString(), DEFAULT_PROVIDER_NAME));
			setAlgorithimName(props.getProperty(PropertyNaming.PROP_ALGORITHM_NAME.toString(), DEFAULT_ALGORITHM_NAME));
			setPrivateKeyFile(props.getProperty(PropertyNaming.PROP_PRIVATE_KEYFILE.toString(), DEFAULT_PRIVATE_KEY_FILE));
			setPublicKeyFile(props.getProperty(PropertyNaming.PROP_PUBLIC_KEYFILE.toString(), DEFAULT_PUBLIC_KEY_FILE));	
			setPublicKey(PEMCertificateUtils.getPublicKey(getPublicKeyFile(), getPassphrase(), getProviderName()));
			setPrivateKey(PEMCertificateUtils.getPrivateKey(getPrivateKeyFile(), getPassphrase(), getProviderName()));
		} catch (Exception ex) {
			throw new ConfigurationException(ex.fillInStackTrace());
		}	
	}
	
	@Override
	public String encrypt(final String cleartext) {
		if (cleartext == null) {
			return cleartext;
		}
		try {
			Cipher cipher = Cipher.getInstance(getAlgorithimName(),getProviderName());
		    cipher.init(Cipher.ENCRYPT_MODE, getPrivateKey());
		    return addNamespacePrefix(Hex.toHexString(cipher.doFinal(cleartext.getBytes())));	    
		} catch (Exception ex) { 
			ex.printStackTrace(); 
		}
		return cleartext; 
	}

	@Override
	public String decrypt(final String cyphertext){
		if (cyphertext == null) {
			return cyphertext;
		}
		try {
			Cipher cipher = Cipher.getInstance(getAlgorithimName(),getProviderName());
		    cipher.init(Cipher.DECRYPT_MODE, getPrivateKey());
		    return new String(cipher.doFinal(Hex.decode(removeNamespacePrefix(cyphertext))));			    
		} catch (Exception ex) { 
			ex.printStackTrace(); 
		}
		return cyphertext;	
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

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}

}
