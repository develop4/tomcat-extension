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
package com.develop4.security.utils;

import java.util.Properties;

import org.bouncycastle.util.encoders.Base64;

public class Base64Decoder implements Decoder {

	public static final String INFO = "Base64 Decoder Test v1.00";

    public static final String NAME = "B64";
    
    private static final String NAMESPACE = "base64://";
    
	public Base64Decoder() {
	}
	
	public String getNamespace() {
		return NAMESPACE;
	}
	
	public String getDescription() {
		return "Base64 Decoder for Testing";
	}
	
	public void init(String passphrase, Properties props) throws Exception {
		// -- TODO Auto-generated method stub
	}
	
	public String encrypt(String cleartext) throws Exception {
		return NAMESPACE+cleartext;
	}

	public String decrypt(String cyphertext) throws Exception {
		if (cyphertext != null && cyphertext.startsWith(NAMESPACE)) {
			String stripped = cyphertext.replace(NAMESPACE, "");
			
			return new String(Base64.decode(stripped.getBytes()));
		}
		return cyphertext;	
	}


}
