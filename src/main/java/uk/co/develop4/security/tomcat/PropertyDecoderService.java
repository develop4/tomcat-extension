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
import java.net.URL;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;

import org.apache.tomcat.util.IntrospectionUtils;
import org.apache.tomcat.util.IntrospectionUtils.PropertySource;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.encoders.Base64;

import uk.co.develop4.security.utils.PropertyNaming;
import uk.co.develop4.security.utils.decoders.Decoder;
import uk.co.develop4.security.utils.decoders.DecoderUtils;
import uk.co.develop4.security.utils.readers.Reader;

/**
 * PropertyDecoderService
 * 
 * This is the main class that needs plugged into the Tomcat Servers <i>catalina.properties</i> file.  See
 * the entry below for the configuration additions required to activate the property introspector.
 * 
 * <pre>
 *   org.apache.tomcat.util.digester.PROPERTY_SOURCE=uk.co.develop4.security.tomcat.PropertyDecoderService
 *   uk.co.develop4.security.tomcat.PropertyDecoderService.configuration=file://${catalina.base}/restricted/settings/decoder.properties
 * </pre>
 * 
 * @author william timpany
 *
 */
public class PropertyDecoderService extends BaseService implements IntrospectionUtils.PropertySource {

	/* Configuration Constants */
	public static final String CONSOLE_TIMEOUT_PROP = PropertyDecoderService.class.getName() + "." + PropertyNaming.PROP_CONSOLE_TIMEOUT;
	public static final String PASSPHRASE_PROP 		= PropertyDecoderService.class.getName() + "." + PropertyNaming.PROP_PASSPHRASE;
	public static final String PASSPHRASE_FILE_PROP = PropertyDecoderService.class.getName() + "." + PropertyNaming.PROP_PASSPHRASE_FILE;
	public static final String CONFIGURATION_PROP 	= PropertyDecoderService.class.getName() + "." + PropertyNaming.PROP_CONFIGURATION;
	public static final String PROPERTIES_PROP 		= PropertyDecoderService.class.getName() + "." + PropertyNaming.PROP_PROPERTIES;
	public static final String DECODER_PROP 		= PropertyDecoderService.class.getName() + "." + PropertyNaming.PROP_DECODER;
	public static final String DEBUG_PROP 			= PropertyDecoderService.class.getName() + "." + PropertyNaming.PROP_DEBUG;
	public static final String LOGGING_PROP 		= PropertyDecoderService.class.getName() + "." + PropertyNaming.PROP_LOGGING;

	/* Default Values */
	protected static final Pattern patternUri 		= Pattern.compile("(^\\S+://)");
	protected static final Pattern patternUriWithSuffix = Pattern.compile("(^\\S+:\\S+//)");


	protected static final long DEFAULT_TIMEOUT_VALUE = 30000l;
	protected static final String DEFAULT_KEY = "hex://446576656c6f7034546563686e6f6c6f67696573";

	protected Properties properties = new Properties();
	protected Properties propertiesCommand = new Properties();
	protected Properties configuration = new Properties();
	protected Map<String, Decoder> decoders = new HashMap<String, Decoder>();

	protected String defaultKey = null;
	protected long consoleTimeout = 30000l;
		
	public Map<String, Decoder> getDecoders() {
		return this.decoders;
	}
	private String introspectProperty(String value) {
		if (value == null) {
			return value;
		} else {
			return IntrospectionUtils.replaceProperties(value, null, 
					new IntrospectionUtils.PropertySource[] {
						new SystemPropertySource(), 
						new LocalPropertySource(this.configuration),
						new LocalPropertySource(this.properties) 
						}
					);
		}
	}

	public PropertyDecoderService() throws Exception {
		
		// -- Add BouncyCastle provider if it is missing
		if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
		
		// -- Check if the Unlimited Strength if installed
		if (Cipher.getMaxAllowedKeyLength("AES") == 128) {
			warn("JCE Unlimited Strength Jurisdiction Policy files have not been installed.");
		}

		/* get the configuration file to be used for setting up the decoder */
		String configurationFile = System.getProperty(CONFIGURATION_PROP);
		if (configurationFile == null) {
			configurationFile = this.configuration.getProperty(CONFIGURATION_PROP);
		}
		if (configurationFile != null) {
			configurationFile = introspectProperty(configurationFile);

			File pFile = DecoderUtils.isFile(configurationFile);
			if (pFile != null) {
				info("Activate configuration file reader for file: \"" + pFile.getCanonicalPath() + "\"");
				this.configuration = DecoderUtils.readFileProperties(pFile);
			} else {
				throw new IllegalArgumentException("Unable to load configuration file:" + configurationFile);
			}

		}
		
		this.setLogging(Boolean.parseBoolean(this.configuration.getProperty(LOGGING_PROP, "false")));
		this.setDebug(Boolean.parseBoolean(this.configuration.getProperty(DEBUG_PROP, "false")));

		/* Get the console timeout value to be used as the default */
		String csTimeout = System.getProperty(CONSOLE_TIMEOUT_PROP);
		if (csTimeout == null) {
			csTimeout = this.configuration.getProperty(CONSOLE_TIMEOUT_PROP);
		}
		if (csTimeout != null) {
			csTimeout = csTimeout.trim();
			String tmpTimeout = introspectProperty(csTimeout);
			if (tmpTimeout != null) {
				this.consoleTimeout = Long.getLong(tmpTimeout, DEFAULT_TIMEOUT_VALUE).longValue();
			}
		}

		/* set the default key */
		this.defaultKey = decode(this.defaultKey);
		
		/* Get the master key to be used as the default value */
		String passphrase = System.getProperty(PASSPHRASE_PROP);
		if (passphrase == null) {
			passphrase = this.configuration.getProperty(PASSPHRASE_PROP);
		}
		if (passphrase != null) {
			this.defaultKey = decode(passphrase.trim());
		}
		
		/* Get the file where the master key is stored */
		String passphraseFile = System.getProperty(PASSPHRASE_FILE_PROP);
		if (passphraseFile == null) {
			passphraseFile = this.configuration.getProperty(PASSPHRASE_FILE_PROP);
		}
		if (passphraseFile != null) {
			passphraseFile = introspectProperty(passphraseFile.trim());
		}
		
		if (passphrase == null && passphraseFile != null) {
			String localPassPhrase = null;
			// -- Read passphrase from console 
			if (passphraseFile.startsWith("console")) {
				info("Activate console passphrase reader");
				localPassPhrase = DecoderUtils.readConsole(this.consoleTimeout);
				if (localPassPhrase == null) {
					throw new NullPointerException("Invalid passphrase provided by console input.");
				} 
			} 
			// -- Read the password from the secure file 
			if (passphraseFile.startsWith("file")) {
				File pFile = DecoderUtils.isFile(passphraseFile);
				if (pFile != null) {
					info("Activate file passphrase reader from: \"" + pFile.getCanonicalPath() + "\"");
					localPassPhrase = DecoderUtils.readFileValue(pFile);
					if (localPassPhrase == null) {
						throw new NullPointerException("Invalid passphrase provided by file input.");
					}
				}
			} 
			// -- Read the password from a secure url
			if (passphraseFile.startsWith("http")) {
				URL pUrl = DecoderUtils.isUrl(passphraseFile);
				if (pUrl != null) {
					info("Activate url passphrase reader from: \"" + pUrl.toString() + "\"");
					localPassPhrase = DecoderUtils.readUrlValue(pUrl);
					if (localPassPhrase == null) {
						throw new NullPointerException("Invalid passphrase provided by file input.");
					}
				}
			} 
			if (localPassPhrase != null) {
				this.defaultKey = decode(localPassPhrase.trim());
			} 
		} 
		// -- debug("Passphrase initialized: " + this.defaultKey);
		
		// -- load properties from providers specified
		for (int i = 50; i > 0; i--) {
			String propertiesMapping = PROPERTIES_PROP + "." + i;
			String className = this.configuration.getProperty(propertiesMapping);
			try {
				if (className != null) {
					Reader tmpReader = (Reader) Class.forName(className).newInstance();
					if (tmpReader != null) {
						info("Activate reader: \"" + tmpReader.toString());
						// -- TODO : only pass parameters that as specific for the reader
						Properties tmpProperties = new Properties();
						for (String myKey : this.configuration.stringPropertyNames()) {
							// -- Transfer property settings that begin with the reader mapping to ensure 
							// -- properties settings do not leak between readers.
							if (myKey.startsWith(propertiesMapping)) {
								String myNewKey = myKey.replace(propertiesMapping+".", "");
								tmpProperties.put(myNewKey, introspectProperty(this.configuration.getProperty(myKey)));
							}
						}
						tmpReader.init(this.defaultKey, tmpProperties);
						this.properties.putAll(tmpReader.read());
					}
				}
			} catch (Exception ex) {
				warn("Failed to instanciate reader class: " + className);
				ex.printStackTrace();
			}

		}

		// -- load the possible decoder mappings here, in reverse order.
		// -- this will ensure that the correct precedence is preserved.
		for (int i = 50; i > 0; i--) {
			String decoderMapping = DECODER_PROP + "." + i;
			String className = this.configuration.getProperty(decoderMapping);
			try {
				if (className != null) {
					Decoder tmpDecoder = (Decoder) Class.forName(className).newInstance();
					if (tmpDecoder != null) {
						info("Activate decoder: \"" + tmpDecoder.toString());
						// -- TODO : only pass parameters that as specific for the decoder
						Properties tmpProperties = new Properties();
						for (String myKey : this.configuration.stringPropertyNames()) {
							// -- Transfer property settings that begin with the decoder mapping to ensure 
							// -- properties settings do not leak between decoders.
							if (myKey.startsWith(decoderMapping)) {
								String myNewKey = myKey.replace(decoderMapping+".", "");
								tmpProperties.put(myNewKey, introspectProperty(this.configuration.getProperty(myKey)));
							}
						}
						tmpDecoder.init(this.defaultKey, tmpProperties);
						this.decoders.put(tmpDecoder.getNamespace(), tmpDecoder);
						info("Install decoder: \"" + tmpDecoder.toString());
					}
				}
			} catch (Exception ex) {
				warn("Failed to instanciate decoder class: " + className);
				ex.printStackTrace();
			}
		}
	}

	public String decode(String cyphertext) {
		// -- info("Decode value: " + cyphertext);
		if (cyphertext == null) {
			return null;
		}
		try {
			if (cyphertext.startsWith(PropertyNaming.PROP_BASE64.toString())) {
				String stripped = cyphertext.replace(PropertyNaming.PROP_BASE64.toString(), "");
				String cleartext = new String(Base64.decode(stripped.getBytes()));
				// -- debug("Decoded using Base64: " + cleartext);
				return cleartext;
			} else if (cyphertext.startsWith(PropertyNaming.PROP_HEX.toString())) {
				String stripped = cyphertext.replace(PropertyNaming.PROP_HEX.toString(), "");
				String cleartext = new String(Hex.decode(stripped.getBytes()));
				// -- debug("Decoded using Hex: " + cleartext);
				return cleartext;
			} else {
				return cyphertext;
			}
		} catch (Exception dex) {
			info("Problem trying to decode the text: " + dex.getMessage());
		}
		return cyphertext;
	}

	public String getProperty(String key) {
		if (key == null) {
			return null;
		}
		String val = this.properties.getProperty(key);
		if (val == null) {
			if (System.getProperty(key) == null) {
				return null;
			}
			val = System.getProperty(key);
		}
		return decodePropertyValue(key, val);
	}

	public String decodePropertyValue(String key, String value) {
		if (value == null) {
			return value;
		}
		try {
			info("Handle Key: \"" + key + "\"  Value: \"" + value + "\"");
			Matcher matcher = patternUri.matcher(value);
			if (matcher.find()) {
				String namespaceKey = matcher.group(1);
				Decoder decoder = this.decoders.get(namespaceKey);
				if (decoder != null) {
					debug("Namespace for decoder found: " + namespaceKey + "  decoder: " + decoder.toString());
					value = decoder.decrypt(value);
					debug("Decoded Key: \"" + key + "\"  Value: \"" + value + "\"");
				}
			}
			matcher = patternUriWithSuffix.matcher(value);
			if (matcher.find()) {
				String namespaceKey = matcher.group(1);
				Decoder decoder = this.decoders.get(namespaceKey);
				if (decoder != null) {
					debug("Namespace for decoder found: " + namespaceKey + "  decoder: " + decoder.toString());
					value = decoder.decrypt(value);
					debug("Decoded Key: \"" + key + "\"  Value: \"" + value + "\"");
				}
			}
			return value;
		} catch (Exception x) {
			debug("Oops decoding has failed:" + key);
			throw new IllegalArgumentException("Oops decoding has failed:" + key, x);
		}
	}
	
	public String encodePropertyValue(String namespaceKey, String value) {
		return encodePropertyValue(namespaceKey, value, null);
	}
	
	public String encodePropertyValue(String namespaceKey, String value, String label) {
		if (value == null) {
			return value;
		}
		try {
			info("Handle Namespace: \"" + namespaceKey + "\"  Value: \"" + value + "\"");
			Decoder decoder = this.decoders.get(namespaceKey);
			if (decoder != null) {
				debug("Namespace for encoder found: " + namespaceKey + "  encoder: " + decoder.toString());
				value = decoder.encrypt(value, label);
				debug("Encoded Value: \"" + value + "\"");
			} else {
				warn("No Encoder found for namespace: \"" + namespaceKey + "\"");
			}
			return value;
		} catch (Exception x) {
			warn("Oops encoding has failed:" + namespaceKey);
			throw new IllegalArgumentException("Oops encoding has failed:" + namespaceKey, x);
		}
	}

}