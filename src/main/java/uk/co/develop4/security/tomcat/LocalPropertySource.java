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

import java.util.Properties;

import org.apache.tomcat.util.IntrospectionUtils;

/**
 * 
 * @author wtimpany
 *
 */
public class LocalPropertySource implements IntrospectionUtils.PropertySource {
	private Properties props;

	LocalPropertySource(Properties props) {
		this.props = props;
	}

	public String getProperty(String key) {
		return this.props.getProperty(key);
	}
}
