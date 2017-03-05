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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.SealedObject;

import org.bouncycastle.util.encoders.Hex;
import org.jasypt.encryption.StringEncryptor;

import uk.co.develop4.security.ConfigurationException;
import uk.co.develop4.security.ConversionException;
import uk.co.develop4.security.utils.PEMCertificateUtils;
import uk.co.develop4.security.utils.PropertyNaming;
import uk.co.develop4.security.utils.PropertySealed;

/**
 * 
 * RSA Sealed Codec - wraps the PropertySealed object to add a "name" and "date"
 * parameter. This allows the encoded value to contain extra data. e.g. when the
 * password was encoded.
 * 
 * PropertySealed public String label; public String value; public Date date;
 * 
 * @author wtimpany
 *
 */
public class RSASealedCodec extends BaseCodec implements Codec, StringEncryptor {

	private final static Logger logger = Logger.getLogger(RSASealedCodec.class.getName());

	private final String DEFAULT_DESCRIPTION = "RSA Codec";
	private final String DEFAULT_NAMESPACE = "rsa:sealed//";
	private final String DEFAULT_PASSPHRASE = "446576656C6F7034546563686E6F6C6F67696573";
	private final String DEFAULT_PROVIDER_NAME = "BC";
	private final String DEFAULT_ALGORITHM_NAME = "RSA/None/PKCS1Padding";

	private final String DEFAULT_PRIVATE_KEY_FILE = "private.pem";
	private final String DEFAULT_PUBLIC_KEY_FILE = "public.pem";

	private String passphrase;
	private String providerName;
	private String algorithimName;
	private String privateKeyFile;
	private String publicKeyFile;

	private PrivateKey privateKey;
	private PublicKey publicKey;

	public Map<String, Set<String>> getRequiredParameters() {
		Map<String, Set<String>> requiredParams = new HashMap<String, Set<String>>();
		Set<String> encodeParams = new HashSet<String>(Arrays.asList(
				PropertyNaming.PROP_PASSPHRASE.toString(), 
				PropertyNaming.PROP_PRIVATE_KEYFILE.toString()
			));
		Set<String> decodeParams = new HashSet<String>(Arrays.asList(
				PropertyNaming.PROP_PUBLIC_KEYFILE.toString()
			));
		requiredParams.put("encode", encodeParams);
		requiredParams.put("decode", decodeParams);
		return requiredParams;
	}

	public Map<String, Set<String>> getOptionalParameters() {
		Map<String, Set<String>> optionalParams = new HashMap<String, Set<String>>();
		Set<String> encodeParams = new HashSet<String>(Arrays.asList(
				PropertyNaming.PROP_PROVIDER_NAME.toString(), 
				PropertyNaming.PROP_ALGORITHM_NAME.toString(),
				PropertyNaming.PROP_LOGGING.toString()
			));
		Set<String> decodeParams = new HashSet<String>(Arrays.asList(
				PropertyNaming.PROP_PROVIDER_NAME.toString(), 
				PropertyNaming.PROP_ALGORITHM_NAME.toString(),
				PropertyNaming.PROP_LOGGING.toString()
			));
		optionalParams.put("encode", encodeParams);
		optionalParams.put("decode", decodeParams);
		return optionalParams;
	}

	public RSASealedCodec() {
	}

	@Override
	public void init(final Properties props) throws ConfigurationException {
		try {
			setLoggerLevel(logger, props.getProperty(PropertyNaming.PROP_LOGGING.toString()));
			
			setPassphrase(props.getProperty(PropertyNaming.PROP_PASSPHRASE.toString(), DEFAULT_PASSPHRASE));
			setNamespace(new Namespace(props.getProperty(PropertyNaming.PROP_NAMESPACE.toString(), DEFAULT_NAMESPACE)));
			setDescription(props.getProperty(PropertyNaming.PROP_DESCRIPTION.toString(), DEFAULT_DESCRIPTION));
			setProviderName(props.getProperty(PropertyNaming.PROP_PROVIDER_NAME.toString(), DEFAULT_PROVIDER_NAME));
			setAlgorithimName(props.getProperty(PropertyNaming.PROP_ALGORITHM_NAME.toString(), DEFAULT_ALGORITHM_NAME));
			setPrivateKeyFile(props.getProperty(PropertyNaming.PROP_PRIVATE_KEYFILE.toString(), DEFAULT_PRIVATE_KEY_FILE));
			setPublicKeyFile(props.getProperty(PropertyNaming.PROP_PUBLIC_KEYFILE.toString(), DEFAULT_PUBLIC_KEY_FILE));

			setPublicKey(PEMCertificateUtils.getPublicKey(getPublicKeyFile(), getPassphrase(), getProviderName()));
			setPrivateKey(PEMCertificateUtils.getPrivateKey(getPrivateKeyFile(), getPassphrase(), getProviderName()));
		} catch (Exception ex) {
			logger.log(Level.SEVERE, "Failed to initialized Codec: {0}", getNamespace());
			throw new ConfigurationException("Property initialization failed", ex.fillInStackTrace());
		}
	}

	@Override
	public String encrypt(final String cleartext) {
		if (cleartext == null) {
			return cleartext;
		}
		try {
			Cipher cipher = Cipher.getInstance(getAlgorithimName(), getProviderName());
			cipher.init(Cipher.ENCRYPT_MODE, getPublicKey());
			PropertySealed sealable = new PropertySealed(cleartext, new Date());
			SealedObject sealed = new SealedObject(sealable, cipher);
			return addNamespacePrefix(sealedToHex(sealed));
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return cleartext;
	}
	
	@Override
	public String decrypt(final String cyphertext) {
		if (cyphertext == null) {
			return cyphertext;
		}
		try {
			Cipher cipher = Cipher.getInstance(getAlgorithimName(), getProviderName());
			cipher.init(Cipher.DECRYPT_MODE, getPrivateKey());
			SealedObject sealed = hexToSealed(removeNamespacePrefix(cyphertext));
			PropertySealed sealable = (PropertySealed) sealed.getObject(cipher);
			return sealable.getValue();		    
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return cyphertext;
	}

	public String sealedToHex(SealedObject sealedObject) throws ConversionException {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		try (ObjectOutputStream oos = new ObjectOutputStream(bos);) {
			oos.writeObject(sealedObject);
			return Hex.toHexString(bos.toByteArray());
		} catch (Exception ex) {
			throw new ConversionException(ex.getCause());
		}
	}

	public SealedObject hexToSealed(String textValue) throws ConversionException {
		try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(Hex.decode(textValue)));) {
			return (SealedObject) ois.readObject();
		} catch (Exception ex) {
			throw new ConversionException(ex.getCause());
		}
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

	public void setLoggerLevel(Level level) {
		logger.setLevel(level);
	}
}
