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

import uk.co.develop4.security.utils.PropertyNaming;

/**
 * 
 * @author wtimpany
 *
 */
public class RSADecoder extends BaseDecoder implements Decoder, StringEncryptor {

	private static final String INFO 		= "RSA Decoder Test v1.00";
	private String NAMESPACE 				= "rsa://";
	private String DESCRIPTION 				= "RSA";
    
    private String DEFAULT_NAMESPACE 				= "rsa://";
    private String DEFAULT_PASSPHRASE 				= "446576656C6F7034546563686E6F6C6F67696573";
    private String DEFAULT_PROVIDER_NAME 			= "BC";
    private String DEFAULT_ALGORITHM_NAME 			= "RSA/None/PKCS1Padding";
    
    private String DEFAULT_PRIVATE_KEY_FILE 		= "private.pem";
    private String DEFAULT_PUBLIC_KEY_FILE 			= "public.pem";
        
    private String passphrase;
    private String providerName;
    private String algorithimName;
    private String privateKeyFile;
    private String publicKeyFile;
    
    private PrivateKey privateKey;
    private PublicKey publicKey;
    
    private Properties properties;
    
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
		
		this.setLogging(Boolean.parseBoolean(properties.getProperty(PropertyNaming.PROP_LOGGING.toString(), "false")));
		this.setDebug(Boolean.parseBoolean(properties.getProperty((PropertyNaming.PROP_DEBUG.toString()), "false")));
		
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
		this.setPublicKey(DecoderUtils.getPublicKey(this.getPublicKeyFile(), this.getPassphrase(), this.getProviderName()));
		this.setPrivateKey(DecoderUtils.getPrivateKey(this.getPrivateKeyFile(), this.getPassphrase(), this.getProviderName()));
		
		if (!this.getNamespace().equalsIgnoreCase(DEFAULT_NAMESPACE)) {
			warn("Namespace Override: Default: " + DEFAULT_NAMESPACE + " \t New: " + this.getNamespace());
		}
	}
	
	public String encrypt(String clearText) {
		return encrypt(clearText, null);
	}
	
	public String encrypt(String clearText, String label) {
		String cypherText = clearText;
		if (clearText == null) {
			return null;
		}
		try {
			Cipher cipher = Cipher.getInstance(this.getAlgorithimName(),this.getProviderName());
		    cipher.init(Cipher.ENCRYPT_MODE, this.getPrivateKey());
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
				Cipher cipher = Cipher.getInstance(this.getAlgorithimName(),this.getProviderName());
			    cipher.init(Cipher.DECRYPT_MODE, this.getPrivateKey());
			    byte[] plainBytes =  cipher.doFinal(Hex.decode(stripped));			    
				plainText = new String(plainBytes);
			}
		} catch (Exception ex) { 
			ex.printStackTrace(); 
		}
		return plainText;	
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
