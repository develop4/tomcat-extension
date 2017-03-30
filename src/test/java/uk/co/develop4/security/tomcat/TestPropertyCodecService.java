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

import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

import org.junit.Test;

import uk.co.develop4.security.test.BaseTest;

/**
 * Unit test for simple configuration
 */
public class TestPropertyCodecService  extends BaseTest{

	/**
	 * Create the test case
	 */
	@Test
	public void initializeServiceFromPropertiesFile() throws Exception {
		URL configUrl = getClass().getResource("/restricted/settings/codec.properties");
		Path configPath = Paths.get(configUrl.toURI());
		System.setProperty(PropertyCodecService.CONFIGURATION_PROP, configPath.toString());

		String catalinaBase = getClass().getResource("/").getPath();
		if (catalinaBase.endsWith("/")) {
			catalinaBase = catalinaBase.substring(0, catalinaBase.length() - 1);
		}
		System.setProperty("catalina.base", catalinaBase);

		System.setProperty("org.apache.tomcat.util.digester.PROPERTY_SOURCE", "uk.co.develop4.security.tomcat.PropertyCodecService");

		PropertyCodecService service = new PropertyCodecService();

		Properties props = new Properties();
		URL url = getClass().getResource("/context.properties");
		props.load(url.openStream());
		for (Object key : props.keySet()) {
			String myKey = key.toString();
			service.getProperty(props.getProperty(myKey).replaceAll("[${}]", ""));
		}

	}

}
