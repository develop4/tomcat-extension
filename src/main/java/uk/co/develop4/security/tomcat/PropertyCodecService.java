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
package uk.co.develop4.security.tomcat;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Optional;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import javax.crypto.Cipher;

import org.apache.tomcat.util.IntrospectionUtils;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import uk.co.develop4.security.ConfigurationException;
import uk.co.develop4.security.codecs.Codec;
import uk.co.develop4.security.codecs.CodecFactory;
import uk.co.develop4.security.codecs.CodecRegistry;
import uk.co.develop4.security.codecs.Namespace;
import uk.co.develop4.security.readers.Reader;
import uk.co.develop4.security.readers.ReaderFactory;
import uk.co.develop4.security.utils.IOCodecUtils;
import uk.co.develop4.security.utils.PropertyNaming;

/**
 * PropertyCodecService
 * 
 * This is the main class that needs plugged into the Tomcat Servers <i>catalina.properties</i> file.  See
 * the entry below for the configuration additions required to activate the property introspector.
 * 
 * <pre>
 *   org.apache.tomcat.util.digester.PROPERTY_SOURCE=uk.co.develop4.security.tomcat.PropertyCodecService
 *   uk.co.develop4.security.tomcat.PropertyCodecService.configuration=${catalina.base}/restricted/settings/codec.properties
 * </pre>
 * 
 * @author wtimpany
 *
 */
public class PropertyCodecService extends BaseService implements IntrospectionUtils.PropertySource {

	private final static Logger logger = Logger.getLogger(PropertyCodecService.class.getName());

	/* Configuration Constants */
	public static final int    MAX_CODECS           = 50;
	public static final int    MAX_READERS          = 50;
	public static final String CONSOLE_TIMEOUT_PROP = PropertyCodecService.class.getName() + "." + PropertyNaming.PROP_CONSOLE_TIMEOUT;
	public static final String PASSPHRASE_PROP 		= PropertyCodecService.class.getName() + "." + PropertyNaming.PROP_PASSPHRASE;
	public static final String PASSPHRASE_FILE_PROP = PropertyCodecService.class.getName() + "." + PropertyNaming.PROP_PASSPHRASE_FILE;
	public static final String CONFIGURATION_PROP 	= PropertyCodecService.class.getName() + "." + PropertyNaming.PROP_CONFIGURATION;
	public static final String PROPERTIES_PROP 		= PropertyCodecService.class.getName() + "." + PropertyNaming.PROP_PROPERTIES;
	public static final String CODEC_PROP 			= PropertyCodecService.class.getName() + "." + PropertyNaming.PROP_CODEC;
	public static final String DEBUG_PROP 			= PropertyCodecService.class.getName() + "." + PropertyNaming.PROP_DEBUG;
	public static final String LOGGING_PROP 		= PropertyCodecService.class.getName() + "." + PropertyNaming.PROP_LOGGING;
	public static final String SNOOP_PROP 			= PropertyCodecService.class.getName() + "." + PropertyNaming.PROP_SNOOP;

	/* Default Values */
	protected static final Pattern patternUri 			= Pattern.compile("(^\\S+://)");
	protected static final Pattern patternUriWithSuffix = Pattern.compile("(^\\S+:\\S+//)");
	protected static final Pattern patternReaders 		= Pattern.compile(PROPERTIES_PROP+".\\d$");
	protected static final Pattern patternCodecs 		= Pattern.compile(CODEC_PROP+".\\d$");

	protected static final long DEFAULT_TIMEOUT_VALUE = 30000l;
	protected static final String DEFAULT_KEY 	= "hex://446576656c6f7034546563686e6f6c6f67696573";

	protected Properties properties 			= new Properties();
	protected Properties configuration 			= new Properties();
	protected CodecRegistry codecRegistry 		= new CodecRegistry();

	protected String defaultKey 				= null;
	protected long consoleTimeout 				= 30000l;
		
	public CodecRegistry getCodecRegistry() {
		return this.codecRegistry;
	}
	
	private String introspectProperty(String value) {
		if (value == null) {
			return value;
		} else {
			return IntrospectionUtils.replaceProperties(value, null, 
					new IntrospectionUtils.PropertySource[] {
						new SystemPropertySource(), 
						new LocalPropertySource(getConfiguration()),
						new LocalPropertySource(getProperties()) 
						}
					);
		}
	}
	
	private Properties getConfiguration() {
		return this.configuration;
	}
	
	private Properties getProperties() {
		return this.properties;
	}

	public PropertyCodecService() throws Exception {
		
		initialiseUnlimitedStrengthEncryption();
		initialiseConfigurationProperties();
		initialiseDefaultKey(); 
		
		getConfiguration()
			.entrySet()
			.stream()
			.filter(map -> patternReaders.matcher(map.getKey().toString()).matches())
			.forEach(map -> {
				Reader reader = null;
				try {
					reader = ReaderFactory.getReader(map.getValue().toString(), createPropertiesForMapping(map.getKey().toString()));
				} catch (ConfigurationException e) {;}
				addAllPropertiesFromReader(reader);			
			});
		
		getConfiguration()
			.entrySet()
			.stream()
			.filter(map -> patternCodecs.matcher(map.getKey().toString()).matches())
			.forEach(map -> {
				Codec codec = null;
				try {
					codec = CodecFactory.getCodec(map.getValue().toString(), createPropertiesForMapping(map.getKey().toString()));
				} catch (ConfigurationException e) {;}
				addCodecToRegistry(codec);
			});
		
	}

	private void addCodecToRegistry(Codec codec) {
		getCodecRegistry().addCodec(codec);
	}

	private void addAllPropertiesFromReader(Reader reader) {
		getProperties().putAll(reader.read());
		logger.info("Reader add properties: " + reader);
	}
	
	
	/*
	 * The configuration of the default passphrase follows the following priority
	 * (1) System Property
	 * (2) Configuration Property
	 * (3) Master passphrase file
	 * (4) Console input | Http |
	 * otherwise each Codec requires it's own passphrase
	 */
	private void initialiseDefaultKey() throws InterruptedException, IOException {
		
		String localPassPhrase = isNull(System.getProperty(PASSPHRASE_PROP),getConfiguration().getProperty(PASSPHRASE_PROP));
		
		if (localPassPhrase == null) {
			/* Get the file where the master key is stored */
			String passphraseFile = System.getProperty(PASSPHRASE_FILE_PROP);
			if (passphraseFile == null) {
				passphraseFile = getConfiguration().getProperty(PASSPHRASE_FILE_PROP);
			}
			if (passphraseFile != null) {
				passphraseFile = introspectProperty(passphraseFile.trim());
			}
			
			if (passphraseFile != null) {
				if (passphraseFile.startsWith("console")) {
					localPassPhrase = readPassphraseFromConsole(); 
				} else if (passphraseFile.startsWith("http")) {
					// -- Read the password from a secure url
					localPassPhrase = readPassphraseFromURL(passphraseFile, localPassPhrase);
				} else {
					// -- Read the password from the secure file 
					localPassPhrase = readPassphraseFromFile(passphraseFile, localPassPhrase);
				}
				if (localPassPhrase != null) {
					this.defaultKey = deobsuscate(localPassPhrase.trim());
				} 
			}
		}
		if (localPassPhrase != null) {
			this.defaultKey = deobsuscate(localPassPhrase.trim());
		} 
	}

	private String readPassphraseFromFile(String passphraseFile, String localPassPhrase) throws IOException {
		File pFile = IOCodecUtils.isFile(passphraseFile);
		if (pFile != null) {
			logger.info("Activate file passphrase reader from: \"" + pFile.getCanonicalPath() + "\"");
			localPassPhrase = IOCodecUtils.readFileValue(pFile);
			if (localPassPhrase == null) {
				throw new NullPointerException("Invalid passphrase provided by file input.");
			}
		}
		return localPassPhrase;
	}

	private String readPassphraseFromURL(String passphraseFile, String localPassPhrase) throws IOException {
		URL pUrl = IOCodecUtils.isUrl(passphraseFile);
		if (pUrl != null) {
			logger.info("Activate url passphrase reader from: \"" + pUrl.toString() + "\"");
			localPassPhrase = IOCodecUtils.readUrlValue(pUrl);
			if (localPassPhrase == null) {
				throw new NullPointerException("Invalid passphrase provided by file input.");
			}
		}
		return localPassPhrase;
	}

	private String readPassphraseFromConsole() throws InterruptedException, IOException {
		String localPassPhrase;
		/* Get the console timeout value to be used as the default */
		String csTimeout = System.getProperty(CONSOLE_TIMEOUT_PROP);
		if (csTimeout == null) {
			csTimeout = getConfiguration().getProperty(CONSOLE_TIMEOUT_PROP);
		}
		if (csTimeout != null) {
			csTimeout = csTimeout.trim();
			String tmpTimeout = introspectProperty(csTimeout);
			if (tmpTimeout != null) {
				this.consoleTimeout = Long.getLong(tmpTimeout, DEFAULT_TIMEOUT_VALUE).longValue();
			}
		}
		// -- Read passphrase from console 
		logger.info("Activate console passphrase reader");
		localPassPhrase = IOCodecUtils.readConsole(this.consoleTimeout);
		if (localPassPhrase == null) {
			throw new NullPointerException("Invalid passphrase provided by console input.");
		}
		return localPassPhrase;
	}

	private void initialiseConfigurationProperties() throws IOException {
		String configurationFile = System.getProperty(CONFIGURATION_PROP);
		if (configurationFile == null) {
			configurationFile = getConfiguration().getProperty(CONFIGURATION_PROP);
		}
		if (configurationFile != null) {
			configurationFile = introspectProperty(configurationFile);
			File pFile = IOCodecUtils.isFile(configurationFile);
			if (pFile != null) {
				this.configuration = IOCodecUtils.readFileProperties(pFile);
			} else {
				throw new IllegalArgumentException("Unable to load configuration file:" + configurationFile);
			}
			setLoggerLevel(logger, getConfiguration().getProperty(LOGGING_PROP.toString()));
		}
	}

	private Properties createPropertiesForMapping(String propertiesMapping) {
		Properties tmpProperties = new Properties();
		tmpProperties.put(PropertyNaming.PROP_PASSPHRASE.toString(), this.defaultKey);
		String propertiesMappingKey = propertiesMapping+".";
		for (String myKey : getConfiguration().stringPropertyNames()) {
			if (myKey.startsWith(propertiesMappingKey)) {
				String myNewKey = myKey.replace(propertiesMappingKey, "");
				tmpProperties.put(myNewKey, introspectProperty(getConfiguration().getProperty(myKey)));
			}
		}
		return tmpProperties;
	}
	
	private void initialiseUnlimitedStrengthEncryption() throws NoSuchAlgorithmException {
		if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
		if (Cipher.getMaxAllowedKeyLength("AES") == 128) {
			logger.warning("JCE Unlimited Strength Jurisdiction Policy files have not been installed.");
		}
	}

	public String deobsuscate(String cyphertext) {
		if (cyphertext == null) {
			return null;
		}
		try {
			Optional<Namespace> optional = Namespace.valueOf(cyphertext);
			if (optional.isPresent()) {
				Namespace namespace = optional.get();
				String stripped = namespace.removeNamespacePrefix(cyphertext);
				if (namespace.isEqual(PropertyNaming.PROP_BASE64.toString())) {
					return new String(Base64.decode(stripped.getBytes()));
				} else if (namespace.isEqual(PropertyNaming.PROP_HEX.toString())) {
					return new String(Hex.decode(stripped.getBytes()));
				} 
			} 
		} catch (Exception dex) {
			logger.info("Problem trying to decode the text: " + dex.getMessage());
		}
		return cyphertext;
	}

	/**
	 * Implemented from IntrospectionUtils.PropertySource
	 */
	public String getProperty(String key) {
		if (key == null) {
			return null;
		}
		String val = getProperties().getProperty(key);
		if (val == null) {
			if (System.getProperty(key) == null) {
				return null;
			}
			val = System.getProperty(key);
		}
		return decodePropertyValue(key, val);
	}
	
	public String decodePropertyValue(String key, String data) {
		if (data == null) {
			return null;
		}
		String result = data;
		logger.info("Handle Key:  \"" + key + "\"  Data: \"" + data + "\"");
		Optional<Namespace> namespace 	= Namespace.valueOf(data);
		if (namespace.isPresent()) {
			Optional<Codec> codec  			= codecRegistry.getCodec(namespace.get());
			if (codec.isPresent()) {
				result = codec.get().decrypt(data);
				if (isSnoop(logger)) {
					logger.finest("Decoded Key: \"" + key + "\"  Data: \"" + result + "\"");
				} else {
					String partial = result.substring(0, 2) + "........" + result.substring(result.length()-2, result.length());
					logger.fine("Decoded Key: \"" + key + "\"  Data: \"" + partial + "\"");
				}
			}
		}
		return result;
	}
	
	public String encodePropertyValue(Namespace key, String data) {
		if (data == null) {
			return null;
		}
		String result = data;
		logger.info("Handle Namespace:  \"" + key + "\"  Data: \"" + data + "\"");
		Optional<Codec> codec  = codecRegistry.getCodec(key);
		if (codec.isPresent()) {
			result = codec.get().encrypt(data);
			if (isSnoop(logger)) {
				logger.finest("Encoded Namespace: \"" + key + "\"  Data: \"" + result + "\"");
			} else {
				String partial = result.substring(0, 2) + "********" + result.substring(result.length()-2, result.length());
				logger.fine("Encoded Namespace: \"" + key + "\"  Data: \"" + partial + "\"");
			}
		} else {
			logger.warning("No Encoder found for namespace: \"" + key + "\"");
		}
		return result;
	}
	
	protected void setLoggerLevel(Logger log, String level) {
		if (level != null) {
			log.setLevel(Level.parse(level));
		}
	}

}