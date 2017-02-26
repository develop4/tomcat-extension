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
package uk.co.develop4.security.utils;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 
 * @author wtimpany
 *
 */
public class CommonFunctions {
	
	/* Default Values */
	protected static final Pattern patternNameSpace = Pattern.compile("(^\\S+:(\\S+|)//)(\\S+$)");

	public static String extractNameSpace(String value) throws NullPointerException,IllegalArgumentException {
		if (value == null) {
			throw new NullPointerException("Null value passed as parameter.");
		} 
		if (value != null && value.length() == 0) {
			throw new IllegalArgumentException("Zero Length value passed as parameter.");
		} 	
		Matcher matcher = patternNameSpace.matcher(value);
		matcher.find();
		String temp = matcher.group(1); 
		return temp;	
	}
	
	public static String extractSuffix(String value) throws NullPointerException,IllegalArgumentException {
		if (value == null) {
			throw new NullPointerException("Null value passed as parameter.");
		} 
		if (value != null && value.length() == 0) {
			throw new IllegalArgumentException("Zero Length value passed as parameter.");
		} 	
		Matcher matcher = patternNameSpace.matcher(value);
		matcher.find();
		String temp = matcher.group(3); 
		return temp;	
	}
	
	public static String extractSchema(String value) throws NullPointerException,IllegalArgumentException {
		return null;	
	}
	
	public static String extractSubSchema(String value) throws NullPointerException,IllegalArgumentException {
		return null;	
	}
	

}
