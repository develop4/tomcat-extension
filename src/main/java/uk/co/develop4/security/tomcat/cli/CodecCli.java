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
package uk.co.develop4.security.tomcat.cli;

import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import org.jasypt.commons.CommonUtils;

import uk.co.develop4.security.codecs.Codec;
import uk.co.develop4.security.codecs.Namespace;
import uk.co.develop4.security.tomcat.PropertyCodecService;
import uk.co.develop4.security.utils.PropertyNaming;

/**
 * 
 * @author wtimpany
 */
public final class CodecCli {
	
	private CodecCli() {
	}

	public static void main(final String[] args) {
		CodecCli dcli = new CodecCli();
		int status = dcli.run(args);
		System.exit(status);
	}

	public int run(final String[] args) {

		try {
			// -- Convert input parameters into Properties file
			final Set<String> argNames = new HashSet<String>();
			for (PropertyNaming val : PropertyNaming.values()) {
				argNames.add(val.toString());
			}

			final Properties argumentValues = new Properties();
			for (int i = 0; i < args.length; i++) {
				final String key = CommonUtils.substringBefore(args[i], "=");
				final String value = CommonUtils.substringAfter(args[i], "=");
				if (CommonUtils.isEmpty(key) || CommonUtils.isEmpty(value)) {
					throw new IllegalArgumentException("Bad argument: " + args[i]);
				}
				if (argNames.contains(key)) {
					if (value.startsWith("\"") && value.endsWith("\"")) {
						System.setProperty(key, value.substring(1, value.length() - 1));
						argumentValues.setProperty(key, value.substring(1, value.length() - 1));
					} else {
						System.setProperty(key, value);
						argumentValues.setProperty(key, value);
					}
				} else {
					throw new IllegalArgumentException("Bad argument: " + args[i]);
				}
			}

			String catalinaBase = System.getProperty(PropertyNaming.PROP_CATALINA_BASE.toString());

			String sysPropConfig = PropertyCodecService.class.getName() + "." + PropertyNaming.PROP_CONFIGURATION.toString();
			String sysPropProp = PropertyCodecService.class.getName() + "." + PropertyNaming.PROP_PROPERTIES.toString();
			String sysPropPass = PropertyCodecService.class.getName() + "." + PropertyNaming.PROP_PASSPHRASE.toString();

			if (argumentValues.getProperty(PropertyNaming.PROP_CONFIGURATION.toString()) != null) {
				System.setProperty(sysPropConfig, argumentValues.getProperty(PropertyNaming.PROP_CONFIGURATION.toString()));
			} else {
				System.setProperty(sysPropConfig, catalinaBase + "/scripts/codec.properties");
			}
			if (argumentValues.getProperty(PropertyNaming.PROP_PROPERTIES.toString()) != null) {
				System.setProperty(sysPropProp, argumentValues.getProperty(PropertyNaming.PROP_PROPERTIES.toString()));
			}
			if (argumentValues.getProperty(PropertyNaming.PROP_PASSPHRASE.toString()) != null) {
				System.setProperty(sysPropPass, argumentValues.getProperty(PropertyNaming.PROP_PASSPHRASE.toString()));
			}

			PropertyCodecService pds = new PropertyCodecService();

			String namespaceKey = (String) System.getProperty(PropertyNaming.PROP_NAMESPACE.toString());
			String value = (String) System.getProperty(PropertyNaming.PROP_INPUT.toString());
			String action = (String) System.getProperty(PropertyNaming.PROP_ACTION.toString());
			//String passPhrase = (String) System.getProperty(PropertyNaming.PROP_PASSPHRASE.toString());
			String codecFile = (String) System.getProperty(sysPropConfig);

			String coded;
			if ("encode".equalsIgnoreCase(action)) {
				coded = pds.encodePropertyValue(new Namespace(namespaceKey), value);
				System.out.println("------------------------------------------------------------------- ");
				System.out.println("Encrypted Value: " + coded);
				System.out.println("------------------------------------------------------------------- ");
			} else if ("decode".equalsIgnoreCase(action)) {
				coded = pds.decodePropertyValue(namespaceKey, value);
				System.out.println("------------------------------------------------------------------- ");
				System.out.println("Decrypted Value: " + coded);
				System.out.println("------------------------------------------------------------------- ");
			} else {
				System.out.println("------------------------------------------------------------------- ");
				System.out.println("Usage:");
				System.out.println("  codec.sh  action=encode passphrase=<mypassphrase> namespace=<namespace> input=<plaintext>  [configuration=<codec properties>]");
				System.out.println("  codec.sh  action=decode passphrase=<mypassphrase> namespace=<namespace> input=<cyphertext> [configuration=<codec properties>]");
				System.out.println("");
				System.out.println("-- Additional Parameters Based on Codec Specified --");
				System.out.println("   configuration: \"" + codecFile + "\"");
				System.out.println("");
				System.out.println("Supported Codecs: encode");
				System.out.println("");
				for (Codec codec : pds.getCodecRegistry().values()) {
					System.out.println("  Codec: " + codec);
					System.out.println("    Required Parameters: " + codec.getRequiredParameters().get("encode").toString());
					System.out.println("    Optional Parameters: " + codec.getOptionalParameters().get("encode").toString());
					System.out.println("");
				}
				System.out.println("Supported Codecs: decode");
				System.out.println("");
				for (Codec codec : pds.getCodecRegistry().values()) {
					System.out.println("  Codec: " + codec);
					System.out.println("    Required Parameters: " + codec.getRequiredParameters().get("decode").toString());
					System.out.println("    Optional Parameters: " + codec.getOptionalParameters().get("decode").toString());
					System.out.println("");
				}
				System.out.println("------------------------------------------------------------------- ");
				return 1;
			}
		} catch (Exception ex) {
			ex.printStackTrace();
			return 1;
		}
		return 0;
	}

}
