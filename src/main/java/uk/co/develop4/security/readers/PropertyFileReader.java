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

import java.io.File;
import java.util.Arrays;
import java.util.Properties;

import uk.co.develop4.security.utils.IOCodecUtils;
import uk.co.develop4.security.utils.PropertyNaming;

/**
 * 
 * @author william timpany
 * 
 */
public class PropertyFileReader extends BaseReader implements Reader {

	private static final String DEFAULT_PATH_SEPERATOR = ";";

	private String[] fileNames;
	
	public PropertyFileReader () {
	}
	
	public void init(String passphrase, Properties props) {
		
		String pathSeperator = props.getProperty(PropertyNaming.PROP_PATH_SEPERATOR.toString(),DEFAULT_PATH_SEPERATOR);
		String propertyFile = props.getProperty(PropertyNaming.PROP_PATH.toString());
		if (propertyFile != null) {
			this.fileNames = propertyFile.split(pathSeperator);
		}
	}

	public Properties read() {
		//log.info("Load properties from reader: \"" + tmpReader.toString());
		Properties loader = new Properties();
		for(String fileName : fileNames) {
			try {
				File pFile = IOCodecUtils.isFile(fileName);
				if (pFile != null) {
					loader.putAll(IOCodecUtils.readFileProperties(pFile));
				} 
			} catch (Exception ex) {
				System.out.println("Exception: Read application properties reader from: \"" + fileName + "\"");
				System.out.println(ex.getMessage());
			}
		}
		return loader;
	}

	public void write(Properties prop, String path) {	
		throw new UnsupportedOperationException();
	}
	

    @Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("PropertyFileReader [fileNames=");
		builder.append(Arrays.toString(fileNames));
		builder.append("]");
		return builder.toString();
	}

}