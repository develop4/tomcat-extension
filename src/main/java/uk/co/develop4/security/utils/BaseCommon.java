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

import java.io.StringWriter;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

public class BaseCommon {
	
	private static Level getEffectiveLoggerLevel(Logger log) {
		if (log.getLevel() != null) {
			return log.getLevel();
		}
		if (log.getParent().getLevel() != null) {
			return log.getParent().getLevel();
		}
		return Level.WARNING;
	}
	
	public static boolean isSnoop(Logger log) {
		return (getEffectiveLoggerLevel(log).intValue() <= Level.FINEST.intValue());
	}

	public static boolean isTrace(Logger log) {

		return (getEffectiveLoggerLevel(log).intValue() <= Level.FINER.intValue());
	}

	public static boolean isDebug(Logger log) {
		return (getEffectiveLoggerLevel(log).intValue() <= Level.FINE.intValue());
	}

	public static boolean isInfo(Logger log) {
		return (getEffectiveLoggerLevel(log).intValue() <= Level.INFO.intValue());

	}

	public static boolean isWarning(Logger log) {
		return (getEffectiveLoggerLevel(log).intValue() <= Level.WARNING.intValue());

	}

	public static boolean isOff(Logger log) {
		return (getEffectiveLoggerLevel(log).intValue() <= Level.OFF.intValue());

	}
	
	protected void setLoggerLevel(Logger log, String level) {
		if (level != null) {
			log.setLevel(Level.parse(level));
		}
	}

	public static String isNull(String value, String defaultValue) {
		if (value == null) {
			return defaultValue; 
		} else {
			return value;
		}
	}
	
	public static Object isNull(Object value, Object defaultValue ) {
		if (value != null) {
			return value;
		} else {
			return defaultValue;
		}
	}
	
	public static Object isNull(Object value, Object notNullValue, Object defaultValue) {
		if (value != null) {
			return notNullValue;
		} else {
			return defaultValue;
		}
	}
	
	public static String isNull(String value, String notNullValue, String defaultValue) {
		if (value != null) {
			return notNullValue;
		} else {
			return defaultValue;
		}
	}
	

	
	public static String prettryPrintProperties(final Properties props) throws Exception {
		StringWriter sw = new StringWriter();
		props.store(sw,"dump properties");
		return "\n" + sw.toString() + "\n";
	}
 
}
