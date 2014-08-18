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

import java.util.Properties;

import org.apache.commons.validator.routines.UrlValidator;
import org.bouncycastle.util.encoders.Hex;
import org.jasypt.encryption.StringEncryptor;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.Security;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;

/**
 * Common Utilities for use in the decoders
 * 
 * @author williamtimpany
 *
 */
public class DecoderUtils {

	public static String readConsole(long timeout) throws InterruptedException, IOException {
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

	public static File isFile(String fileName) {
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

	public static URL isUrl(String url) {
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

	public static String readFileValue(File file) throws IOException {
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
					System.out.println("Failed to close Reader for File: \"" + file + "\"" + ioe);
				}
			}
		}
		return line;
	}

	public static Properties readFileProperties(File file) throws IOException {
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
					System.out.println("Failed to close Reader for File: \"" + file + "\"" + ioe);
				}
			}
		}
		return returnProperties;
	}

	public static String readUrlValue(URL url) throws IOException {
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
						System.out.println("Failed to close String Reader for URL: \"" + url + "\"" + ioe);
					}
				}
			}
		}
		return returnValue;
	}

	public static Properties readUrlProperties(URL url) throws IOException {
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
						System.out.println("Failed to close Property Reader for URL: \"" + url + "\"" + ioe);
					}
				}
			}
		}
		return returnProperties;
	}

}
