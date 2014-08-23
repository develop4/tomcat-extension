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

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.jasypt.encryption.StringEncryptor;

import uk.co.develop4.security.tomcat.PropertyDecoderService;
import uk.co.develop4.security.utils.PropertyNaming;

public class NullDecoder implements Decoder, StringEncryptor {

	private static org.apache.juli.logging.Log log = org.apache.juli.logging.LogFactory.getLog(NullDecoder.class);

	private static final String INFO 		= "Null Decoder Test v1.00";
	private static final String CLASSNAME 	= NullDecoder.class.getName();
	private String DESCRIPTION 				= "NULL";
	private String NAMESPACE 				= "null://";

    private String DEFAULT_NAMESPACE 		= "null://";

    private String passphrase;

	private Properties properties;
	private boolean debug = false;
    
	public Map<String,Set<String>> getRequiredParameters() {
    	Map<String,Set<String>> requiredParams = new HashMap<String,Set<String>>();
    	Set<String> encodeParams = new HashSet<String>();
    	Set<String> decodeParams = new HashSet<String>();
    	requiredParams.put("encode", encodeParams);
    	requiredParams.put("decode", decodeParams);
    	return requiredParams;
    }
    
    public Map<String,Set<String>> getOptionalParameters() {
    	Map<String,Set<String>> optionalParams = new HashMap<String,Set<String>>();
    	Set<String> encodeParams = new HashSet<String>(Arrays.asList(
    			PropertyNaming.PROP_DEBUG.toString()
    			)) ;
    	Set<String> decodeParams = new HashSet<String>(Arrays.asList(
    			PropertyNaming.PROP_DEBUG.toString()
    			)) ;
    	optionalParams.put("encode", encodeParams);
    	optionalParams.put("decode", decodeParams);
    	return optionalParams;
    }
    
	public NullDecoder() {
	}
	
	public String getNamespace() {
		return NAMESPACE;
	}
	
	public void setNamespace(String namespace) {
		this.NAMESPACE = namespace;
	}
	
	public String getDescription() {
		return DESCRIPTION;
	}
	
	public String getInfo() {
		return INFO;
	}
	
	public void init(final String passphrase, final Properties props)  {
		if(props != null) {
			this.properties = props;
		}
		this.setDebug(Boolean.parseBoolean(properties.getProperty(PropertyNaming.PROP_DEBUG.toString(), "false")));
		if (isDebug()) {
			log.info("Debug mode has been activated:");
		}
		

		this.setNamespace(this.properties.getProperty(PropertyNaming.PROP_NAMESPACE.toString(), DEFAULT_NAMESPACE));
				
		if (isDebug()) {
			for (String myKey : this.properties.stringPropertyNames()) {
				log.info("Properties: key: \"" + myKey + "\" value: \"" + this.properties.getProperty(myKey) + "\"");
			}
		}
	}
	
	public String encrypt(String cleartext)  {
		if (cleartext == null) {
			return null;
		}
		return NAMESPACE+cleartext;
	}

	public String decrypt(String cyphertext)  {
		if (cyphertext != null && cyphertext.startsWith(NAMESPACE)) {
			return cyphertext.replace(NAMESPACE, "");
		}
		return cyphertext;	
	}

	public String getPassphrase() {
		return passphrase;
	}

	public void setPassphrase(final String passphrase) {
		this.passphrase = passphrase;
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
		builder.append("NullDecoder [Namespace:");
		builder.append(getNamespace());
		builder.append(", Description:");
		builder.append(getDescription());
		builder.append(", Info:");
		builder.append(getInfo());
		builder.append("]");
		return builder.toString();
	}

}
