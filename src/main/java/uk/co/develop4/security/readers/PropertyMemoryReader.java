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
package uk.co.develop4.security.readers;

import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 
 * @author william timpany
 *
 */
public class PropertyMemoryReader extends BaseReader implements Reader {

	private final static Logger logger = Logger.getLogger(PropertyMemoryReader.class.getName());

	public PropertyMemoryReader() {
	}

	public void init(Properties props) {
	}

	public Properties read() {
		logger.log(Level.FINE, "Scanning memory: \"Test\"");
		Properties properties = new Properties();
		properties.put("property.memory.reader.test1", "TEST_ONE");
		properties.put("property.memory.reader.test2", "TEST_TWO");
		return properties;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("PropertyMemoryReader");
		return builder.toString();
	}

	public void setLoggerLevel(Level level) {
		logger.setLevel(level);
	}
}
