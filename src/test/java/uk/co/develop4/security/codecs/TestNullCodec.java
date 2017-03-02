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

import static org.junit.Assert.assertEquals;

import java.util.Properties;

import org.junit.Test;

import uk.co.develop4.security.ConfigurationException;

public class TestNullCodec {

	@Test
    public void performValidEncryptAndDecrypt() throws Exception
    {
		Properties propeties = new Properties();
		
		NullCodec codec = new NullCodec();
		codec.init(propeties);
		
		String secret = "XXXxxx TestValue xxxXXX";
		String cyphertext = codec.encrypt(secret);
		String cleartext = codec.decrypt(cyphertext);
		
		assertEquals("Secret equals Cleartext", secret, cleartext);
    }
	
	@Test
    public void initWithNullPassphraseDoesNotThrowException() throws Exception
    {
		NullCodec codec = new NullCodec();
		codec.init(new Properties());

    }
	
	@Test(expected=ConfigurationException.class) 
    public void initWithNullPropertiesThrowsException() throws Exception
    {
		NullCodec codec = new NullCodec();
		codec.init(null);
    }
}
