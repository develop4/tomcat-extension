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

public class NullDecoder implements Decoder {

	public static final String INFO = "Null Decoder Test v1.00";

    public static final String NAME = "NP";
    
    private static final String NAMESPACE = "null://";
    
	public NullDecoder() {
	}
	
	public String getNamespace() {
		return NAMESPACE;
	}
	
	public String getDescription() {
		return "Null Decoder for Testing";
	}
	
	public void init(String passphrase, Properties props) throws Exception {
		// -- TODO Auto-generated method stub
	}
	
	public String encrypt(String cleartext) throws Exception {
		return NAMESPACE+cleartext;
	}

	public String decrypt(String cyphertext) throws Exception {
		if (cyphertext != null && cyphertext.startsWith(NAMESPACE)) {
			return cyphertext.replace(NAMESPACE, "");
		}
		return cyphertext;	}


}
