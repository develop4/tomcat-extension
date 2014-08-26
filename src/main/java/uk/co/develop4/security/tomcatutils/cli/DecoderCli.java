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
package uk.co.develop4.security.tomcatutils.cli;

import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import org.jasypt.commons.CommonUtils;

import uk.co.develop4.security.tomcat.PropertyDecoderService;
import uk.co.develop4.security.utils.PropertyNaming;
import uk.co.develop4.security.utils.decoders.Decoder;

/**
 * 
 * 
 * @author timpwi
 *
 */
public final class DecoderCli {

	// -- TODO : Fix issue with "spaces spaces" in the command parameters.....
	
	private DecoderCli() {
	}

	public static void main(final String[] args) {
		DecoderCli dcli = new DecoderCli();
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

			String sysPropConfig = PropertyDecoderService.class.getName() + "." + PropertyNaming.PROP_CONFIGURATION.toString();
			String sysPropProp = PropertyDecoderService.class.getName() + "." + PropertyNaming.PROP_PROPERTIES.toString();
			String sysPropPass = PropertyDecoderService.class.getName() + "." + PropertyNaming.PROP_PASSPHRASE.toString();

			if (argumentValues.getProperty(PropertyNaming.PROP_CONFIGURATION.toString()) != null) {
				System.setProperty(sysPropConfig, argumentValues.getProperty(PropertyNaming.PROP_CONFIGURATION.toString()));
			} else {
				System.setProperty(sysPropConfig, catalinaBase + "/scripts/decoder.properties");
			}
			if (argumentValues.getProperty(PropertyNaming.PROP_PROPERTIES.toString()) != null) {
				System.setProperty(sysPropProp, argumentValues.getProperty(PropertyNaming.PROP_PROPERTIES.toString()));
			}
			if (argumentValues.getProperty(PropertyNaming.PROP_PASSPHRASE.toString()) != null) {
				System.setProperty(sysPropPass, argumentValues.getProperty(PropertyNaming.PROP_PASSPHRASE.toString()));
			}

			PropertyDecoderService pds = new PropertyDecoderService();

			String namespaceKey = (String) System.getProperty(PropertyNaming.PROP_NAMESPACE.toString());
			String value = (String) System.getProperty(PropertyNaming.PROP_INPUT.toString());
			String action = (String) System.getProperty(PropertyNaming.PROP_ACTION.toString());
			//String passPhrase = (String) System.getProperty(PropertyNaming.PROP_PASSPHRASE.toString());
			String decoderFile = (String) System.getProperty(sysPropConfig);

			String coded;
			if ("encode".equalsIgnoreCase(action)) {
				coded = pds.encodePropertyValue(namespaceKey, value);
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
				System.out.println("  encrypt.sh  action=encode passphrase=<mypassphrase> namespace=<namespace> input=<plaintext>  [configuration=<decoder properties>]");
				System.out.println("  encrypt.sh  action=decode passphrase=<mypassphrase> namespace=<namespace> input=<cyphertext> [configuration=<decoder properties>]");
				System.out.println("");
				System.out.println("-- Additional Parameters Based on Decoder Specified --");
				System.out.println("   configuration: \"" + decoderFile + "\"");
				System.out.println("");
				System.out.println("Supported Decoders: encode");
				System.out.println("");
				for (Decoder decoder : pds.getDecoders().values()) {
					System.out.println("  Decoder: " + decoder);
					System.out.println("    Required Parameters: " + decoder.getRequiredParameters().get("encode").toString());
					System.out.println("    Optional Parameters: " + decoder.getOptionalParameters().get("encode").toString());
					System.out.println("");
				}
				System.out.println("Supported Decoders: decode");
				System.out.println("");
				for (Decoder decoder : pds.getDecoders().values()) {
					System.out.println("  Decoder: " + decoder);
					System.out.println("    Required Parameters: " + decoder.getRequiredParameters().get("decode").toString());
					System.out.println("    Optional Parameters: " + decoder.getOptionalParameters().get("decode").toString());
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
