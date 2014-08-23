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

import java.io.File;
import java.util.Properties;

import uk.co.develop4.security.utils.PropertyNaming;
import uk.co.develop4.security.utils.decoders.DecoderUtils;

/**
 * 
 * @author william timpany
 * 
 */
public class PropertyFileReader implements Reader {

	private static org.apache.juli.logging.Log log = org.apache.juli.logging.LogFactory.getLog(PropertyFileReader.class);

    private static final String DEFAULT_PATH_SEPERATOR = ";";

	private String[] fileNames;
	
	public PropertyFileReader () {
	}
	
	@Override
	public void init(String passphrase, Properties props) {
		
		String pathSeperator = props.getProperty(PropertyNaming.PROP_PATH_SEPERATOR.toString(),DEFAULT_PATH_SEPERATOR);
		String propertyFile = props.getProperty(PropertyNaming.PROP_PATH.toString());
		if (propertyFile != null) {
			this.fileNames = propertyFile.split(pathSeperator);
		}
	}


	@Override
	public Properties read() {
		//log.info("Load properties from reader: \"" + tmpReader.toString());
		Properties loader = new Properties();
		for(String fileName : fileNames) {
			try {
				File pFile = DecoderUtils.isFile(fileName);
				if (pFile != null) {
					loader.putAll(DecoderUtils.readFileProperties(pFile));
					log.info("Read application properties from: \"" + fileName + "\"");
				} else {
					log.info("Failed: Read application properties reader from: \"" + fileName + "\"");
				}
			} catch (Exception ex) {
				log.warn("Exception: Read application properties reader from: \"" + fileName + "\"");
				log.warn(ex.getMessage());
			}
		}
		return loader;
	}

	@Override
	public void write(Properties prop, String path) {	
		throw new UnsupportedOperationException();
	}

}
