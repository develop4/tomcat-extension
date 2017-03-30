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
import static org.junit.Assert.assertNotNull;

import java.util.Optional;
import java.util.Properties;

import org.junit.Test;

import uk.co.develop4.security.test.BaseTest;

public class TestCodecRegistry extends BaseTest  {

	@Test
	public void createRegistry() throws Exception{
		
		String value = "hex://";
		String data  = "hex://5468697320697320612074657374";
		
		CodecRegistry codecRegistry = new CodecRegistry();
		
		Optional<Namespace> namespace = Namespace.valueOf(data);

		assertNotNull(namespace.get());
		assertEquals(value, namespace.get().getValue());
				
		Properties propeties = new Properties();	
		propeties.setProperty("description", "changed me");

		Codec codecIn = CodecFactory.getCodec(HexCodec.class.getName(), propeties);
		
		codecRegistry.addCodec(codecIn);
		
		Optional<Codec> codecOut = codecRegistry.getCodec(codecIn.getNamespace());
		
		assertEquals(codecIn, codecOut.get());

	}

}
