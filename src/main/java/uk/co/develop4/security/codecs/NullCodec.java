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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jasypt.encryption.StringEncryptor;

import uk.co.develop4.security.ConfigurationException;

public class NullCodec extends BaseCodec implements Codec, StringEncryptor {
	    
		private final static Logger logger = Logger.getLogger(NullCodec.class.getName());

	    private final String DEFAULT_NAMESPACE 		= "null://";
	    private final String DEFAULT_DESCRIPTION 	= "Null codec";
	    
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
	    	Set<String> encodeParams = new HashSet<String>() ;
	    	Set<String> decodeParams = new HashSet<String>() ;
	    	optionalParams.put("encode", encodeParams);
	    	optionalParams.put("decode", decodeParams);
	    	return optionalParams;
	    }
	    
		public NullCodec() {
		}
		
		@Override
		public void init(Properties props) throws ConfigurationException {
			try {
				setNamespace(new Namespace(DEFAULT_NAMESPACE));
				setDescription(DEFAULT_DESCRIPTION);
			} catch (Exception ex) {
				logger.log(Level.SEVERE, "Failed to initialized Codec: {0}", getNamespace());
				throw new ConfigurationException(ex.fillInStackTrace());
			}
		}
		
		@Override
		public String encrypt(final String cleartext) {
			return cleartext;
		}

		@Override
		public String decrypt(final String cyphertext)  {
			return cyphertext;
		}
		
		public void setLoggerLevel(Level level) {
			logger.setLevel(level);
		}

}
