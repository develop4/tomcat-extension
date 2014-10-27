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
package uk.co.develop4.security.utils.readers;

import java.util.Properties;

/**
 * 
 * @author william timpany
 *
 */
public class PropertyMemoryReader extends BaseReader implements Reader {

	private Properties properties;	

	public PropertyMemoryReader() {
	}

	public void init(String passphrase, Properties props) {
		this.properties = new Properties();
		this.properties.put("property.memory.reader.test1", "TEST_ONE");
		this.properties.put("property.memory.reader.test2", "TEST_TWO");
	}

	public Properties read() {
		return properties;
	}

	public void write(Properties props, String path) {
		this.properties = props;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("PropertyMemoryReader");
		return builder.toString();
	}

}
