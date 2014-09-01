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

import org.bouncycastle.util.encoders.Hex;
import org.jasypt.encryption.StringEncryptor;

import uk.co.develop4.security.utils.PropertyNaming;

public class HexDecoder extends BaseDecoder implements Decoder, StringEncryptor {
	
	private static final String INFO 		= "Hexadecimal Decoder Test v1.00";
	private String NAMESPACE 				= "hex://";
	private String DESCRIPTION 				= "HEX";

    private String DEFAULT_NAMESPACE 		= "hex://";
 
    private Properties properties;
    
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
    			PropertyNaming.PROP_DEBUG.toString(),
    			PropertyNaming.PROP_LOGGING.toString()
    			)) ;
    	Set<String> decodeParams = new HashSet<String>(Arrays.asList(
    			PropertyNaming.PROP_DEBUG.toString(),
    			PropertyNaming.PROP_LOGGING.toString()
    			)) ;
    	optionalParams.put("encode", encodeParams);
    	optionalParams.put("decode", decodeParams);
    	return optionalParams;
    }
    
	public HexDecoder() {
	}

	public String getNamespace() {
		return NAMESPACE;
	}
	
	public String getDescription() {
		return DESCRIPTION;
	}
	
	public void setNamespace(String namespace) {
		this.NAMESPACE = namespace;
	}
	
	public void setDescription(String description) {
		this.DESCRIPTION = description;
	}
	
	public String getInfo() {
		return INFO;
	}
	
	public void init(String passphrase, Properties props)  {
		if(props != null) {
			this.properties = props;
		}	
		this.setLogging(Boolean.parseBoolean(properties.getProperty(PropertyNaming.PROP_LOGGING.toString(), "false")));
		this.setDebug(Boolean.parseBoolean(properties.getProperty(PropertyNaming.PROP_DEBUG.toString(), "false")));	
		this.setNamespace(this.properties.getProperty(PropertyNaming.PROP_NAMESPACE.toString(), DEFAULT_NAMESPACE));
	}
	
	public String encrypt(String clearText) {
		return encrypt(clearText, null);
	}
	
	public String encrypt(String cleartext, String label) {
		if (cleartext == null) {
			return null;
		}
		return NAMESPACE + new String(Hex.encode(cleartext.getBytes()));
	}

	public String decrypt(String cyphertext) {
		if (cyphertext != null && cyphertext.startsWith(NAMESPACE)) {
			String stripped = cyphertext.replace(NAMESPACE, "");
			return new String(Hex.decode(stripped.getBytes()));
		}
		return cyphertext;	
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("HexDecoder [Namespace:");
		builder.append(getNamespace());
		builder.append(", Description:");
		builder.append(getDescription());
		builder.append(", Info:");
		builder.append(getInfo());
		builder.append("]");
		return builder.toString();
	}

}
