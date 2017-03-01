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

public final class Namespace {

	private final String namespace;
	
	public Namespace(final String namespace) {
		this.namespace = namespace;
	}
	
	public String getNamespace() {
		return this.namespace;
		
	}

	public String removeNamespacePrefix(final String value) {
		return value.replaceAll("^"+getNamespace(), "");
	}
	
	public String addNamespacePrefix(final String value) {
		return getNamespace() + value;
	}
	
	public String addNamespacePrefix(byte[] value) {
		return getNamespace() + new String(value);
	}
	
	public boolean isValueInNamespace(final String cyphertext) {
		if (cyphertext == null ) {
			return false;
		}
		if (cyphertext.startsWith(getNamespace())) {
			return true;
		}
		return false;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((namespace == null) ? 0 : namespace.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof Namespace)) {
			return false;
		}
		Namespace other = (Namespace) obj;
		if (namespace == null) {
			if (other.namespace != null) {
				return false;
			}
		} else if (!namespace.equals(other.namespace)) {
			return false;
		}
		return true;
	}

	
}
