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
package com.develop4.security.utils.decoders;

import java.util.Properties;

import org.jasypt.encryption.StringEncryptor;
import org.jasypt.intf.service.JasyptStatelessService;

public class PBEDecoder implements Decoder, StringEncryptor {
	
	private static org.apache.juli.logging.Log log = org.apache.juli.logging.LogFactory.getLog(PBEDecoder.class);

	public static final String INFO 		= "PBE Decoder Test v1.00";
    public static final String NAMESPACE 	= "pbe://";
    public static final String DESCRIPTION 	= "PBE";
    
    private static final String DEFAULT_PASSPHRASE = "446576656C6F7034546563686E6F6C6F67696573";
    private static final String DEFAULT_PROVIDER_NAME = "BC";
    private static final String DEFAULT_ALGORITHM_NAME = "PBEWITHSHA256AND256BITAES-CBC-BC";
    private static final String DEFAULT_OBTENTION_ITERATIONS = "1000";
    private static final String DEFAULT_PROVIDER_CLASS_NAME = "org.bouncycastle.jce.provider.BouncyCastleProvider";
    private static final String DEFAULT_SALT_GENERATOR_CLASS_NAME = null;
    private static final String DEFAULT_STRING_OUTPUT_TYPE = "hexadecimal";


    
	public static final String PASSPHRASE_PROP = PBEDecoder.class.getName() + ".passphrase";
	public static final String PROVIDER_NAME_PROP = PBEDecoder.class.getName() + ".providerName";
	public static final String PROVIDER_CLASS_NAME_PROP = PBEDecoder.class.getName() + ".providerClassName";
	public static final String ALGORITHM_NAME_PROP = PBEDecoder.class.getName() + ".algorithmName";
	public static final String OBTENTION_ITERATIONS_PROP = PBEDecoder.class.getName() + ".obtentionIterations";
	public static final String SALT_GENERATOR_CLASS_NAME_PROP = PBEDecoder.class.getName() + ".saltGeneratorClassName";
	public static final String STRING_OUTPUT_TYPE_PROP = PBEDecoder.class.getName() + ".stringOutputType";


    private String passphrase;
    private String providerClassName;
    private String providerName;
    private String algorithimName;
    private String saltGeneratorClassName;
    private String obtentionIterations;
    private String stringOutputType;
    private Properties properties;

    private boolean debug = false;
        
	public PBEDecoder() {
	}
	
	public String getInfo() {
		return INFO;
	}
	
	public String getNamespace() {
		return NAMESPACE;
	}
	
	public String getDescription() {
		return "PBE Decoder for Testing";
	}
	
	public void init(final String passphrase, final Properties properties) {
		if(properties != null) {
			this.properties = properties;
		}
		// -- do the stuff, allow overriding the passphrase
		this.setPassphrase(passphrase);
		if (this.getPassphrase() == null){
			this.setPassphrase(this.properties.getProperty(PASSPHRASE_PROP, DEFAULT_PASSPHRASE));
		}
		this.setProviderName(this.properties.getProperty(PROVIDER_NAME_PROP, DEFAULT_PROVIDER_NAME));
		this.setAlgorithimName(this.properties.getProperty(ALGORITHM_NAME_PROP, DEFAULT_ALGORITHM_NAME));
		this.setObtentionIterations(this.properties.getProperty(OBTENTION_ITERATIONS_PROP, DEFAULT_OBTENTION_ITERATIONS));
		this.setProviderClassName(this.properties.getProperty(PROVIDER_CLASS_NAME_PROP, DEFAULT_PROVIDER_CLASS_NAME));
		this.setStringOutputType(this.properties.getProperty(STRING_OUTPUT_TYPE_PROP, DEFAULT_STRING_OUTPUT_TYPE));
		this.setSaltGeneratorClassName(this.properties.getProperty(SALT_GENERATOR_CLASS_NAME_PROP, DEFAULT_SALT_GENERATOR_CLASS_NAME));
		
		if (isDebug()) {
			for (String myKey : this.properties.stringPropertyNames()) {
				log.info("Properties: key: \"" + myKey + "\" value: \"" + this.properties.getProperty(myKey) + "\"");
			}
		}
		
	}
	
	public String encrypt(String cleartext) {
		if (cleartext == null) {
			return null;
		}
		final JasyptStatelessService service = new JasyptStatelessService();
		return NAMESPACE + service.encrypt(
        		cleartext, 
                this.getPassphrase(),
                null,
                null,
                this.getAlgorithimName(),
                null,
                null,
                this.getObtentionIterations(),
                null,
                null,
                this.getSaltGeneratorClassName(),
                null,
                null,
                this.getProviderName(),
                null,
                null,
                this.getProviderClassName(),
                null,
                null,
                this.getStringOutputType(),
                null,
                null);
	}

	public String decrypt(String cyphertext) {
		if (cyphertext != null && cyphertext.startsWith(NAMESPACE)) {
			String stripped = cyphertext.replace(NAMESPACE, "");
			
            final JasyptStatelessService service = new JasyptStatelessService();
            final String cleartext =
                    service.decrypt(
                    		stripped, 
                            this.getPassphrase(),
                            null,
                            null,
                            this.getAlgorithimName(),
                            null,
                            null,
                            this.getObtentionIterations(),
                            null,
                            null,
                            this.getSaltGeneratorClassName(),
                            null,
                            null,
                            this.getProviderName(),
                            null,
                            null,
                            this.getProviderClassName(),
                            null,
                            null,
                            this.getStringOutputType(),
                            null,
                            null);
			return cleartext;
		}
		return cyphertext;	
	}
	

	public String getPassphrase() {
		return passphrase;
	}

	public void setPassphrase(final String passphrase) {
		this.passphrase = passphrase;
	}

	public String getProviderName() {
		return providerName;
	}

	public void setProviderName(final String providerName) {
		this.providerName = providerName;
	}

	public String getAlgorithimName() {
		return algorithimName;
	}

	public void setAlgorithimName(final String algorithimName) {
		this.algorithimName = algorithimName;
	}

	public String getSaltGeneratorClassName() {
		return saltGeneratorClassName;
	}

	public void setSaltGeneratorClassName(final String saltGeneratorClassName) {
		this.saltGeneratorClassName = saltGeneratorClassName;
	}

	public String getObtentionIterations() {
		return obtentionIterations;
	}

	public void setObtentionIterations(final String obtentionIterations) {
		this.obtentionIterations = obtentionIterations;
	}

	public String getProviderClassName() {
		return providerClassName;
	}

	public void setProviderClassName(String providerClassName) {
		this.providerClassName = providerClassName;
	}

	public String getStringOutputType() {
		return stringOutputType;
	}

	public void setStringOutputType(final String stringOutputType) {
		this.stringOutputType = stringOutputType;
	}
	
	public boolean isDebug() {
		return debug;
	}

	public void setDebug(final boolean debug) {
		this.debug = debug;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("PBEDecoder [Namespace:");
		builder.append(getNamespace());
		builder.append(", Description:");
		builder.append(getDescription());
		builder.append(", Info:");
		builder.append(getInfo());
		builder.append("]");
		return builder.toString();
	}

}
