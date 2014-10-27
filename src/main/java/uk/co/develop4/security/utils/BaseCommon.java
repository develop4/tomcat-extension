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

public class BaseCommon {

	private static final String INFO  = "[INFO]  ";
	private static final String WARN  = "[WARN]  ";
	private static final String DEBUG = "[DEBUG] ";
	private static final String ERROR = "[ERROR] ";
	private static final String SNOOP = "[SNOOP] ";

	private boolean snoop 		= false;
	private boolean debug 		= false;
	private boolean error 		= false;
	private boolean logging 	= false;

	
	public boolean isError() {
		return error;
	}

	public void setError(boolean error) {
		this.error = error;
	}

	public boolean isSnoop() {
		return snoop;
	}

	public void setSnoop(final boolean snoop) {
		this.snoop = snoop;
	}
	
	public boolean isDebug() {
		return debug;
	}

	public void setDebug(final boolean debug) {
		this.debug = debug;
	}
	
	public boolean isLogging() {
		return logging;
	}

	public void setLogging(final boolean logging) {
		this.logging 	= logging;
	}
	
	public void info(final String message) {
		if (isLogging()) {
			System.out.println(INFO + message);
		}
	}
	
	public void warn(final String message) {
		if (isLogging()) {
			System.out.println(WARN + message);
		}
	}
	
	public void error(final String message) {
		if (isLogging()) {
			System.out.println(ERROR + message);
		}
	}
	
	public void debug(final String message) {
		if (isDebug()) {
			System.out.println(DEBUG + message);
		}
	}
	
	public void snoop(final String message) {
		if (isSnoop()) {
			System.out.println(SNOOP + message);
		}
	}

}

