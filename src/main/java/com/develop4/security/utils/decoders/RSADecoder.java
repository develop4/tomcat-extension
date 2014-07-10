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

import org.bouncycastle.util.encoders.Hex;
import org.jasypt.encryption.StringEncryptor;

public class RSADecoder implements Decoder, StringEncryptor {

	public static final String INFO 		= "RSA Decoder Test v1.00";
    public static final String NAMESPACE 	= "rsa://";
    public static final String DESCRIPTION 	= "RSA";
    
	public RSADecoder() {
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
	
	public void init(String passphrase, Properties props)  {
		// -- TODO Auto-generated method stub
	}
	
	public String encrypt(String cleartext) {
		if (cleartext == null) {
			return null;
		}
		return NAMESPACE + new String(Hex.encode(cleartext.getBytes()));
	}

	public String decrypt(String cyphertext) {
		if (cyphertext != null && cyphertext.startsWith(NAMESPACE)) {
			String stripped = cyphertext.replace(NAMESPACE, "");
			
			return new String(stripped);
		}
		return cyphertext;	
	}

	
	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("RSADecoder [Namespace:");
		builder.append(getNamespace());
		builder.append(", Description:");
		builder.append(getDescription());
		builder.append(", Info:");
		builder.append(getInfo());
		builder.append("]");
		return builder.toString();
	}


}
