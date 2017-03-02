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
 * Read individual property items from a directory.  Rather than being name value pairs the "file name" will be
 * used as a property key with the "file content" being the value.  The specified directories will be scanned, to
 * create a Properties object, loading up all the individual files as property name/value pairs.  The properties object
 * will then be scanned and decrypted as usual, when the properties are expanded by the codecs.
 * 
 * e.g.
 * 
 * Directory:		/tmp/secure/properties/propertyset1
 * Files:			my.property.one
 * 					my.property.two
 * File Contents:	pbe://jtwefvcqbxewfjfcbewgjrtgcehrfbxywfvxfeahgdxvfxjtwFDXBWjedtxjvw
 * 
 * @author william timpany
 * 
 */
public class PropertyDirectoryReader extends BaseReader implements Reader {

	private static final String DEFAULT_PATH_SEPERATOR = ";";

	private String[] directoyNames;
	
	public PropertyDirectoryReader () {
	}
	
	public void init(Properties props) {
		
		String pathSeperator = props.getProperty(PropertyNaming.PROP_PATH_SEPERATOR.toString(),DEFAULT_PATH_SEPERATOR);
		String propertyFile = props.getProperty(PropertyNaming.PROP_PATH.toString());
		if (propertyFile != null) {
			this.directoyNames = propertyFile.split(pathSeperator);
		}
	}

	public Properties read() {
		Properties loader = new Properties();
		for(String directoryName : directoyNames) {
			try {
				File pDirectory = IOCodecUtils.isDirectory(directoryName);
				if (pDirectory != null) {
					debug("Scanning Directory: " + pDirectory.getName());
					File[] fileList = pDirectory.listFiles();
					for(File pFile : fileList) {
						String pKey = pFile.getName();
						debug("Scanning File: " + pKey);
						String pValue = IOCodecUtils.readFileValue(pFile);
						loader.put(pKey, pValue);
					}	
				} 
			} catch (Exception ex) {
				error("Exception: Read application properties reader from: \"" + directoryName + "\"");
				error(ex.getMessage());
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
		builder.append("PropertyDirectoryReader [directoyNames=");
		builder.append(Arrays.toString(directoyNames));
		builder.append("]");
		return builder.toString();
	}

}
