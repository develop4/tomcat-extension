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
package uk.co.develop4.security.codecs;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jasypt.encryption.StringEncryptor;

import uk.co.develop4.security.ConfigurationException;
import uk.co.develop4.security.utils.PropertyNaming;

/**
 * 
 * @author wtimpany
 *
 */
public class ExampleCodec extends BaseCodec implements Codec, StringEncryptor {
    
	private final static Logger logger = Logger.getLogger(ExampleCodec.class.getName());

    private final String DEFAULT_NAMESPACE 		= "example://";
    private final String DEFAULT_DESCRIPTION 	= "Example codec";
    
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
    			PropertyNaming.PROP_LOGGING.toString()
    			)) ;
    	Set<String> decodeParams = new HashSet<String>(Arrays.asList(
    			PropertyNaming.PROP_LOGGING.toString()
    			)) ;
    	optionalParams.put("encode", encodeParams);
    	optionalParams.put("decode", decodeParams);
    	return optionalParams;
    }
    
	public ExampleCodec() {
	}
	
	@Override
	public void init(Properties props) throws ConfigurationException {
		try {
			setLoggerLevel(logger, props.getProperty(PropertyNaming.PROP_LOGGING.toString()));
			
			setNamespace(new Namespace(props.getProperty(PropertyNaming.PROP_NAMESPACE.toString(), DEFAULT_NAMESPACE)));
			setDescription(props.getProperty(PropertyNaming.PROP_DESCRIPTION.toString(), DEFAULT_DESCRIPTION));
		} catch (Exception ex) {
			logger.log(Level.SEVERE, "Failed to initialized Codec: {0}", getNamespace());
			throw new ConfigurationException(ex.fillInStackTrace());
		}
	}
	
	@Override
	public String encrypt(final String cleartext) {
		if (cleartext == null) {
			return null;
		}
		return addNamespacePrefix(cleartext);
	}

	@Override
	public String decrypt(final String cyphertext)  {
		if (cyphertext == null) {
			return null;
		}
		return removeNamespacePrefix(cyphertext);
	}
	
	public void setLoggerLevel(Level level) {
		logger.setLevel(level);
	}

}
