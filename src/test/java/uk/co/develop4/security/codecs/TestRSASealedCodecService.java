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

import uk.co.develop4.security.test.BaseTest;

/**
 * Unit test for simple configuration
 */
public class TestRSASealedCodecService extends BaseTest {
	
	@Test
	public void performValidEncryptAndDecrypt() throws Exception {
		String cleartext = "XXXxxxTESTxxxXXX";

		String privateKeyFile = getClass().getResource("/restricted/keystore/privateOne.pem").getPath();
		String publicKeyFile  = getClass().getResource("/restricted/keystore/publicOne.pem").getPath();

		Properties properties = new Properties();
		properties.put("logging", "FINEST");
		properties.put("passphrase", "CHANGEIT");
		properties.put("namespace", "rsa:sealed//");
		properties.put("privateKeyFile", privateKeyFile);
		properties.put("publicKeyFile",  publicKeyFile);
		
		Codec codec = CodecFactory.getCodec(RSASealedCodec.class.getName(), properties);
		
		String cyphertextTemp = codec.encrypt(cleartext);
		String cleartextTemp = codec.decrypt(cyphertextTemp);
		
		assertEquals(cleartext, cleartextTemp);
	}
	
	@Test
	public void performValidDecryptFromFixedCyphertext() throws Exception {
		String cleartext = "XXXxxxTESTxxxXXX";
		String cyphertext = "rsa:sealed//aced0005737200196a617661782e63727970746f2e5365616c65644f626a6563743e363da6c3b754700200045b000d656e636f646564506172616d737400025b425b0010656e63727970746564436f6e74656e7471007e00014c0009706172616d73416c677400124c6a6176612f6c616e672f537472696e673b4c00077365616c416c6771007e0002787070757200025b42acf317f8060854e00200007870000001008b8239b096712453447c026e9a84bd67ccae27b70b739d13fb9efd416e047ec49faf8996332f5114ba25b3eb6deb47919c7262999d5ba84e4e939ae9e891c476a37b67663b7bba8a8826ef8a6c271c1e7720d9443fa7428eb16cf1a2f4b6251917145e76f1e9b0b8b376e9d24bd7dd34458fcfaac2585237ae3fe891fefe1532a25b236c6475841e2553392bbe84027e065655762dda8e9fc8c8e40f37d5a4edb08d347d591c5a35f091e852097118d7802c09d5fa11af51042f4d89124d62116726a1dc5b5d5de295f72547d6a1d91479cacc910715019ac6552f132ba8648032ddb1424863706f8d7e6a99e3ddc42c455850921e7cddfda4fc40e325b547fa707400155253412f4e6f6e652f504b43533150616464696e67";

		String privateKeyFile = getClass().getResource("/restricted/keystore/privateOne.pem").getPath();
		String publicKeyFile  = getClass().getResource("/restricted/keystore/publicOne.pem").getPath();

		Properties properties = new Properties();
		properties.put("logging", "FINEST");
		properties.put("passphrase", "CHANGEIT");
		properties.put("namespace", "rsa:sealed//");
		properties.put("privateKeyFile", privateKeyFile);
		properties.put("publicKeyFile",  publicKeyFile);
		
		Codec codec = CodecFactory.getCodec(RSASealedCodec.class.getName(), properties);
		
		String cleartextTemp = codec.decrypt(cyphertext);
		
		assertEquals(cleartext, cleartextTemp);
	}

}
