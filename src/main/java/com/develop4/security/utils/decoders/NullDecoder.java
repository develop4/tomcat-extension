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

public class NullDecoder implements Decoder {

	private static org.apache.juli.logging.Log log = org.apache.juli.logging.LogFactory.getLog(NullDecoder.class);

	public static final String INFO = "Null Decoder Test v1.00";
    public static final String NAME = "NP";
    public static final String NAMESPACE = "null://";
    
	public static final String DEBUG_PROP = NullDecoder.class.getName() + ".debug";

	private boolean debug = false;
    
	public NullDecoder() {
	}
	
	public void init(final String passphrase, final Properties properties) throws Exception {
		if(properties != null) {
			this.setDebug(Boolean.parseBoolean(properties.getProperty(DEBUG_PROP, "false")));
		}
		if (this.isDebug()) {
			log.info("Debug mode has been activated:");
		}
	}
	
	public String getNamespace() {
		return NAMESPACE;
	}
	
	public String getDescription() {
		return "Null Decoder for Testing";
	}
	
	public String encrypt(String cleartext) throws Exception {
		return NAMESPACE+cleartext;
	}

	public String decrypt(String cyphertext) throws Exception {
		if (cyphertext != null && cyphertext.startsWith(NAMESPACE)) {
			return cyphertext.replace(NAMESPACE, "");
		}
		return cyphertext;	}

	public boolean isDebug() {
		return debug;
	}

	public void setDebug(final boolean debug) {
		this.debug = debug;
	}


}
