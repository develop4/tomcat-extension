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

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class Namespace {

	private final String value;
	
	private static final Pattern patternUri 		= Pattern.compile("((^[a-zA-Z0-9]+://)|(^[a-zA-Z0-9]+:[a-zA-Z0-9]+//))");
	
	public Namespace(final String value) {
		this.value = value;
	}
	
	public static Optional<Namespace> extractNamespace(String value) {
		try {
			Matcher matcher = patternUri.matcher(value);
			if (matcher.find()) {
				return Optional.ofNullable(new Namespace(matcher.group(1)));
			}
		} catch (IndexOutOfBoundsException ex) {
			// No namespace found so return Optional
		}
		return Optional.empty();
	}
	
	public String getValue() {
		return this.value;
		
	}

	public String removeNamespacePrefix(final String data) {
		return data.replaceAll("^"+getValue(), "");
	}
	
	public String addNamespacePrefix(final String data) {
		return getValue() + data;
	}
	
	public String addNamespacePrefix(byte[] data) {
		return getValue() + new String(data);
	}
	
	public boolean isValueInNamespace(final String cyphertext) {
		if (cyphertext == null ) {
			return false;
		}
		if (cyphertext.startsWith(getValue())) {
			return true;
		}
		return false;
	}
	
	public boolean isEqual(String value) {
		return this.value.equals(value);
	}
	

	@Override
	public String toString() {
		return value;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((value == null) ? 0 : value.hashCode());
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
		if (value == null) {
			if (other.value != null) {
				return false;
			}
		} else if (!value.equals(other.value)) {
			return false;
		}
		return true;
	}

	
}
