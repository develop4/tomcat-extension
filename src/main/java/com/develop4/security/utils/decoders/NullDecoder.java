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

public class NullDecoder implements Decoder, StringEncryptor {

	private static org.apache.juli.logging.Log log = org.apache.juli.logging.LogFactory.getLog(NullDecoder.class);

	public static final String INFO 		= "Null Decoder Test v1.00";
    public static final String DESCRIPTION 	= "NULL";
    public static final String NAMESPACE 	= "null://";
    
	public static final String DEBUG_PROP = NullDecoder.class.getName() + ".debug";

	private boolean debug = false;
    
	public NullDecoder() {
	}
	
	public String getNamespace() {
		return NAMESPACE;
	}
	
	public String getDescription() {
		return DESCRIPTION;
	}
	
	public String getInfo() {
		return INFO;
	}
	
	public void init(final String passphrase, final Properties properties)  {
		if(properties != null) {
			this.setDebug(Boolean.parseBoolean(properties.getProperty(DEBUG_PROP, "false")));
		}
		if (isDebug()) {
			log.info("Debug mode has been activated:");
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
		return cyphertext;	}

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
