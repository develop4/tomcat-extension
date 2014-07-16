/* Licensed under the Apache License, Version 2.0 (the "License");
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
 */
package com.develop4.security.tomcat;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.validator.routines.UrlValidator;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.IntrospectionUtils;
import org.apache.tomcat.util.IntrospectionUtils.PropertySource;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.encoders.Base64;

import com.develop4.security.utils.decoders.Decoder;

public class PropertyDecoderService implements IntrospectionUtils.PropertySource {

	private static Log log = LogFactory.getLog(PropertyDecoderService.class);

	/* Configuration Constants */
	protected static final String CONSOLE_TIMEOUT_PROP = PropertyDecoderService.class.getName() + ".consoleTimeout";
	protected static final String PASSPHRASE_PROP = PropertyDecoderService.class.getName() + ".passphrase";
	protected static final String CONFIGURATION_PROP = PropertyDecoderService.class.getName() + ".configuration";
	protected static final String PROPERTIES_PROP = PropertyDecoderService.class.getName() + ".properties";
	protected static final String DECODER_PROP = PropertyDecoderService.class.getName() + ".decoder";

	/* Default Values */
	private static final String BASE64 = "base64://";
	private static final String HEX = "hex://";
	private static final Pattern patternUri = Pattern.compile("(^\\S+://)");

	protected static final long DEFAULT_TIMEOUT_VALUE = 30000l;
	protected static final String DEFAULT_KEY = "446576656c6f7034546563686e6f6c6f67696573";

	private Properties properties = new Properties();
	private Properties configuration = new Properties();
	private Map<String, Decoder> decoders = new HashMap<String, Decoder>();

	private String defaultKey = DEFAULT_KEY;
	private long consoleTimeout = 30000l;
	
	private boolean debug = false;
	
	private String introspectProperty(String value) {
		if (value == null) {
			return value;
		} else {
			return IntrospectionUtils.replaceProperties(value, null, 
					new IntrospectionUtils.PropertySource[] {
						new SystemPropertySource(), 
						new LocalPropertySource(this.configuration) 
						}
					);
		}
	}

	public PropertyDecoderService() throws Exception {
		log.info("======================================================================");
		log.info("SecurePropertyDigester Initializing");

		boolean bob = log.isDebugEnabled();
		boolean bobb = log.isTraceEnabled();

		/* get the configuration file to be used for setting up the decoder */
		String configurationFile = System.getProperty(CONFIGURATION_PROP);
		if (configurationFile == null) {
			configurationFile = this.configuration.getProperty(CONFIGURATION_PROP);
		}
		if (configurationFile != null) {
			configurationFile = introspectProperty(configurationFile);

			File pFile = isFile(configurationFile);
			if (pFile != null) {
				log.info("Activate configuration file reader for file: \"" + pFile.getCanonicalPath() + "\"");
				this.configuration = readFileProperties(pFile);
			} else {
				throw new IllegalArgumentException("Unable to load fonfiguration file:" + configurationFile);
			}

		}

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

		/* Get the master key to be used as the default value */
		String passphrase = System.getProperty(PASSPHRASE_PROP);
		if (passphrase == null) {
			passphrase = this.configuration.getProperty(PASSPHRASE_PROP);
		}
		if (passphrase != null) {
			passphrase = passphrase.trim();
			if ("console".equals(passphrase)) {
				log.info("Activate console passphrase reader");
				String tmpPassphrase = readConsole(this.consoleTimeout);
				if (tmpPassphrase == null) {
					throw new NullPointerException("Invalid passphrase provided by console input.");
				} else {
					this.defaultKey = tmpPassphrase;
				}
			} else {
				String tmpPassphrase = introspectProperty(passphrase);
				if (tmpPassphrase != null) {
					File pFile = isFile(tmpPassphrase);
					if (pFile != null) {
						log.info("Activate file passphrase reader from: \"" + pFile.getCanonicalPath() + "\"");
						this.defaultKey = readFileValue(pFile);
					} else {
						URL pUrl = isUrl(tmpPassphrase);
						if (pUrl != null) {
							log.info("Activate url passphrase reader from: \"" + pUrl.toString() + "\"");
							this.defaultKey = readUrlValue(pUrl);
						} else {
							log.info("Activate passphrase from memory");
						}
					}
					this.defaultKey = decode(this.defaultKey);
				}
			}
		}
		if (log.isDebugEnabled()) {
			log.info("Passphrase initialized: " + this.defaultKey);
		}

		/* get the property file to be used for all application properties */
		String propertyFile = System.getProperty(PROPERTIES_PROP);
		if (propertyFile == null) {
			propertyFile = this.configuration.getProperty(PROPERTIES_PROP);
		}
		if (propertyFile != null) {
			propertyFile = introspectProperty(propertyFile);
			File pFile = isFile(propertyFile);
			if (pFile != null) {
				log.info("Activate file application properties reader from: \"" + pFile.getCanonicalPath() + "\"");
				this.properties = readFileProperties(pFile);
			} else {
				URL pUrl = isUrl(propertyFile);
				if (pUrl != null) {
					log.info("Activate url application properties reader from: \"" + pUrl.toString() + "\"");
					this.properties = readUrlProperties(pUrl);
				}
			}
		}

		// -- TODO: load all the possible decoder mappings here, in reverse
		// order.
		for (int i = 20; i > 0; i--) {
			String className = this.configuration.getProperty(DECODER_PROP + "." + i);
			try {
				if (className != null) {
					Decoder tmpDecoder = (Decoder) Class.forName(className).newInstance();
					if (tmpDecoder != null) {
						log.info("Activate decoder: \"" + tmpDecoder.toString());
						Properties tmpProperties = new Properties();
						for (String myKey : this.properties.stringPropertyNames()) {
							// -- Transfer property settings that begin with the decoder classname to ensure 
							// -- properties settings do not leak between decoders.
							if (myKey.startsWith(className)) {
								tmpProperties.put(myKey, introspectProperty(this.properties.getProperty(myKey)));
							}
						}
						tmpDecoder.init(this.defaultKey, tmpProperties);
						this.decoders.put(tmpDecoder.getNamespace(), tmpDecoder);
					}
				}
			} catch (Exception ex) {
				log.error("Failed to instanciate decoder class: " + className);
			}

		}

		log.info("SecurePropertyDigester Initialized");
		log.info("======================================================================");
	}

	public String decode(String cyphertext) {
		log.info("Decode value: " + cyphertext);
		if (cyphertext == null) {
			return null;
		}
		try {
			if (cyphertext.startsWith(BASE64)) {
				String stripped = cyphertext.replace(BASE64, "");
				String cleartext = new String(Base64.decode(stripped.getBytes()));
				if (log.isDebugEnabled()) {
					log.debug("Decoded using Base64: " + cleartext);
				}
				return cleartext;
			} else if (cyphertext.startsWith(HEX)) {
				String stripped = cyphertext.replace(HEX, "");
				String cleartext = new String(Hex.decode(stripped.getBytes()));
				if (log.isDebugEnabled()) {
					log.debug("Decoded using Hex: " + cleartext);
				}
				return cleartext;
			} else {
				return cyphertext;
			}
		} catch (Exception dex) {
			log.info("Problem trying to decode the text: " + dex.getMessage());
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
			if (log.isInfoEnabled()) {
				log.info("Handle Key: \"" + key + "\"  Value: \"" + value + "\"");
			}
			
			Matcher matcher = patternUri.matcher(value);
			if (matcher.find()) {
				String namespaceKey = matcher.group(1);
				Decoder decoder = this.decoders.get(namespaceKey);
				if (decoder != null) {
					if (isDebug()) {
						log.info("Namespace for decoder found: " + namespaceKey + "  decoder: " + decoder.toString());
					}
					value = decoder.decrypt(value);
					if (isDebug()) {
						log.info("Decoded Key: \"" + key + "\"  Value: \"" + value + "\"");
					}
				}
			}

			return value;
		} catch (Exception x) {
			log.fatal("Oops decoding has failed:" + key, x);
			throw new IllegalArgumentException("Oops decoding has failed:" + key, x);
		}
	}

	public String readConsole(long timeout) throws InterruptedException, IOException {
		BufferedReader consoleReader = new BufferedReader(new InputStreamReader(System.in));
		System.out.print("Please enter the bootstrap passphrase: ");
		long start = System.currentTimeMillis();
		while (System.currentTimeMillis() - start < timeout) {
			if (!consoleReader.ready()) {
				Thread.sleep(200L);
			} else {
				String key = consoleReader.readLine();
				return key;
			}
		}
		return null;
	}

	public File isFile(String fileName) {
		File file = new File(fileName);
		if ((file.exists()) && (file.isFile()) && (file.isAbsolute() && file.canRead())) {
			return file;
		} else {
			try {
				URI tmpUri = new URI(fileName);
				file = new File(tmpUri);
				if ((file.exists()) && (file.isFile()) && (file.isAbsolute() && file.canRead())) {
					return file;
				}
			} catch (Exception ex) {
				;
			}
		}
		return null;
	}

	public URL isUrl(String url) {
		String[] schemes = { "http", "https" };
		UrlValidator urlValidator = new UrlValidator(schemes);
		if (urlValidator.isValid(url)) {
			try {
				URL u = new URL(url);
				return u;
			} catch (MalformedURLException ex) {
				// log.warn("url is invalid: \"" + url + "\"");
			}
		} else {
			// log.warn("url is invalid: \"" + url + "\"");
		}
		return null;
	}

	public String readFileValue(File file) throws IOException {
		BufferedReader reader = null;
		String line = null;
		try {
			FileReader fr = new FileReader(file);
			reader = new BufferedReader(fr);
			line = reader.readLine();
		} finally {
			if (reader != null) {
				try {
					reader.close();
				} catch (IOException ioe) {
					log.warn("Failed to close Reader for File: \"" + file + "\"", ioe);
				}
			}
		}
		return line;
	}

	public Properties readFileProperties(File file) throws IOException {
		Properties returnProperties = new Properties();
		BufferedReader reader = null;
		try {
			reader = new BufferedReader(new FileReader(file));
			returnProperties.load(reader);
		} finally {
			if (reader != null) {
				try {
					reader.close();
				} catch (IOException ioe) {
					log.warn("Failed to close Reader for File: \"" + file + "\"", ioe);
				}
			}
		}
		return returnProperties;
	}

	public String readUrlValue(URL url) throws IOException {
		String returnValue = null;
		if (url != null) {
			BufferedReader reader = null;
			String line = null;
			StringBuffer sb = new StringBuffer();
			try {
				reader = new BufferedReader(new InputStreamReader(url.openStream()));
				while ((line = reader.readLine()) != null) {
					sb.append(line);
				}
				returnValue = sb.toString();
			} finally {
				if (reader != null) {
					try {
						reader.close();
					} catch (IOException ioe) {
						log.warn("Failed to close String Reader for URL: \"" + url + "\"", ioe);
					}
				}
			}
		}
		return returnValue;
	}

	public Properties readUrlProperties(URL url) throws IOException {
		Properties returnProperties = new Properties();
		if (url != null) {
			BufferedReader reader = null;
			try {
				reader = new BufferedReader(new InputStreamReader(url.openStream()));
				returnProperties.load(reader);
			} finally {
				if (reader != null) {
					try {
						reader.close();
					} catch (IOException ioe) {
						log.warn("Failed to close Property Reader for URL: \"" + url + "\"", ioe);
					}
				}
			}
		}
		return returnProperties;
	}

	public boolean isDebug() {
		return this.debug;
	}

	public void setDebug(boolean debug) {
		this.debug = debug;
	}
}
