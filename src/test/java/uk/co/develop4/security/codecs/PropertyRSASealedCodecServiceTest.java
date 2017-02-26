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

import org.junit.Test;

import uk.co.develop4.security.tomcat.PropertyCodecService;

/**
 * Unit test for simple configuration
 */
public class PropertyRSASealedCodecServiceTest
{
	
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
	@Test
    public void basicTest()
    {
		try {			
			String testValue = "XXXxxxTESTxxxXXX";
			
			String configPath = getClass().getResource("/restricted/settings/codec.properties").getPath();
			System.setProperty(PropertyCodecService.CONFIGURATION_PROP, configPath);
			
			String catalinaBase = getClass().getResource("/").getPath();
			if (catalinaBase.endsWith("/")) {
				catalinaBase = catalinaBase.substring(0, catalinaBase.length()-1);
			}
			System.setProperty("catalina.base", catalinaBase);
			
			PropertyCodecService pds = new PropertyCodecService();
			
			String coded = pds.encodePropertyValue("rsa:sealed//", testValue);
			String decoded = pds.decodePropertyValue("rsa:sealed//", coded);
			
			assertEquals(testValue, decoded);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
    }

}
