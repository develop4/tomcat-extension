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

import uk.co.develop4.security.ConfigurationException;

public class ReaderFactory {

	private final static Logger logger = Logger.getLogger(ReaderFactory.class.getName());

	public static Reader getReader(String classname, Properties properties) throws ConfigurationException{
		Reader reader = null;
		try {
			reader = (Reader) Class.forName(classname).newInstance();
			reader.init(properties);
		} catch (Exception ex) {
			logger.log(Level.WARNING, "Failed to create Reader: \"{0}\" message: \"{1}\"", new Object[] { classname, ex.getMessage() });
			throw new ConfigurationException(ex.getCause());
		}
		return reader;
	}

}
