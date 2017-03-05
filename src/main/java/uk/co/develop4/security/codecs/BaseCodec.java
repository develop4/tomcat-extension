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

import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import uk.co.develop4.security.ConfigurationException;
import uk.co.develop4.security.utils.BaseCommon;

public abstract class BaseCodec extends BaseCommon {
	
	private Namespace namespace;
	private String description;

	public Namespace getNamespace() {
		return this.namespace;
	}

	public String getDescription() {
		return this.description;
	}

	public void setNamespace(final Namespace namespace) {
		this.namespace = namespace;
	}

	public void setDescription(final String description) {
		this.description = description;
	}

	protected String removeNamespacePrefix(final String value) {
		return namespace.removeNamespacePrefix(value);
	}
	
	protected String addNamespacePrefix(final String value) {
		return namespace.addNamespacePrefix(value);
	}
	
	protected String addNamespacePrefix(byte[] value) {
		return namespace.addNamespacePrefix(new String(value));
	}
	
	protected boolean isValueInNamespace(final String cyphertext) {
		if (cyphertext == null ) {
			return false;
		}
		if (namespace.isValueInNamespace(cyphertext)) {
			return true;
		}
		return false;
	}
	

	public abstract void init(final Properties props) throws ConfigurationException;
	
	public abstract String encrypt(final String cleartext);

	public abstract String decrypt(final String cyphertext);

	
	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append(this.getClass().getSimpleName());
		builder.append("[Namespace: \"");
		builder.append(getNamespace());
		builder.append("\", Description: \"");
		builder.append(getDescription());
		builder.append("\"]");
		return builder.toString();
	}

}
