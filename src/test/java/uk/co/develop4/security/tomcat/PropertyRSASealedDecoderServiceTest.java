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
package uk.co.develop4.security.tomcat;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

/**
 * Unit test for simple configuration
 */
public class PropertyRSASealedDecoderServiceTest
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
			
			String configPath = getClass().getResource("/restricted/settings/decoder.properties").getPath();
			System.setProperty(PropertyDecoderService.CONFIGURATION_PROP, configPath);
			
			String catalinaBase = getClass().getResource("/").getPath();
			System.setProperty("catalina.base", catalinaBase);
			
			PropertyDecoderService pds = new PropertyDecoderService();
			
			String coded = pds.encodePropertyValue("rsa:sealed//", testValue, "LabelForSealedValue");
			String decoded = pds.decodePropertyValue("rsa:sealed//", coded);
			
			assertEquals(testValue, decoded);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
    }

}
