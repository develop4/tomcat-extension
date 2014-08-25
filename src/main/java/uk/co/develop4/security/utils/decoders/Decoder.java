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

import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * 
 * @author william timpany
 *
 */
public abstract interface Decoder {
	
	public abstract String getInfo();

	public abstract String getNamespace();
	
	public abstract String getDescription();
	
	public abstract void init(String passphrase, Properties props);
	
	public abstract String encrypt(String plaintext);
	
	public abstract String encrypt(String plaintext, String label);

	public abstract String decrypt(String cyphertext);
	
	public abstract Map<String,Set<String>> getRequiredParameters();
	
	public abstract Map<String,Set<String>> getOptionalParameters();
	
}
