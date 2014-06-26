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
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Properties;

import org.apache.commons.validator.routines.UrlValidator;
import org.apache.tomcat.util.IntrospectionUtils;
import org.apache.tomcat.util.IntrospectionUtils.PropertySource;


import com.develop4.security.utils.Decoder;

public class SecurePropertyDigester implements IntrospectionUtils.PropertySource {

	private static org.apache.juli.logging.Log log = org.apache.juli.logging.LogFactory.getLog(SecurePropertyDigester.class);

	/* Configuration Constants */
	protected static final String consoleTimeout = SecurePropertyDigester.class.getName() + ".consoleTimeout";
	protected static final String bootstrapPassphrase = SecurePropertyDigester.class.getName() + ".bootstrapPassphrase";
	protected static final String bootstrapPassphraseDecoder = SecurePropertyDigester.class.getName() + ".bootstrapPassphraseDecoder";

	protected static final String propertyfile = SecurePropertyDigester.class.getName() + ".propertyfile";

	private Properties properties = new Properties();
	private Decoder decoder = null;

	public SecurePropertyDigester() throws Exception {
		log.info("SecurePropertyDigester Initializing");

		String bootstrapKey = System.getProperty(bootstrapPassphrase);
		if (bootstrapKey == null) {
			throw new NullPointerException("Missing key:" + bootstrapPassphrase);
		}
		bootstrapKey = IntrospectionUtils.replaceProperties(bootstrapKey, null, new IntrospectionUtils.PropertySource[] { new SystemPropertySource() });

		String propfile = System.getProperty(propertyfile);
		if (propfile != null) {
			propfile = IntrospectionUtils.replaceProperties(propfile, null,
					new IntrospectionUtils.PropertySource[] { new SystemPropertySource() });
			File pf = isFile(propfile);
			if ((pf != null) && (pf.canRead())) {
				FileInputStream fis = null;
				try {
					fis = new FileInputStream(pf);
					this.properties.load(fis);
				} finally {
					if (fis != null) {
						try {
							fis.close();
						} catch (IOException ioe) {
							log.warn("Failed to close input stream for file [" + pf + "]", ioe);
						}
					}
				}
			}
		}
		
		// -- TODO:  load all the possible decoder mappings here
		
		log.info("SecurePropertyDigester Initialized");
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
			// -- TODO: Add all the decoding code here but for now just return
			// the value and print out some debugging info
			log.info("Handle Key: \"" + key + "\"  Value: \"" + value + "\"");

			return value;
		} catch (Exception x) {
			log.fatal("Oops decoding has failed:" + key, x);
			throw new IllegalArgumentException("Oops decoding has failed:" + key, x);
		}
	}

	public String readConsole() throws InterruptedException, IOException {
		long timeout = Long.getLong(consoleTimeout, 35000L).longValue();
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		System.out.print("Please enter the bootstrap passphrase: ");
		long start = System.currentTimeMillis();
		// -- If the user does not input a value before the timeout period then
		// continue
		while (System.currentTimeMillis() - start < timeout) {
			if (!br.ready()) {
				Thread.sleep(200L);
			} else {
				String key = br.readLine();
				return key;
			}
		}
		return null;
	}

	public File isFile(String file) {
		File f = new File(file);
		if ((f.exists()) && (f.isFile()) && (f.isAbsolute())) {
			return f;
		} else {
			log.warn("file is invalid: \"" + file + "\"");
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
				log.warn("url is invalid: \"" + url + "\"");
			}
		} else {
			log.warn("url is invalid: \"" + url + "\"");
		}
		return null;
	}

	public String readFile(File f) throws IOException {
		BufferedReader reader = null;
		String line = null;
		try {
			FileReader fr = new FileReader(f);
			reader = new BufferedReader(fr);
			line = reader.readLine();
		} finally {
			if (reader != null) {
				try {
					reader.close();
				} catch (IOException ioe) {
					log.warn("Failed to close Reader for file [" + f + "]", ioe);
				}
			}
		}
		return line;
	}

}
