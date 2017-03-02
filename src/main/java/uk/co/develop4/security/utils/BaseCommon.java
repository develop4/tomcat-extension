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

import java.util.logging.Level;
import java.util.logging.Logger;

public class BaseCommon {

	public boolean isSnoop(Logger log) {
		return (log.getLevel().intValue() <= Level.FINEST.intValue());
	}

	public static boolean isTrace(Logger log) {
		return (log.getLevel().intValue() <= Level.FINER.intValue());
	}

	public static boolean isDebug(Logger log) {
		return (log.getLevel().intValue() <= Level.FINE.intValue());
	}

	public static boolean isInfo(Logger log) {
		return (log.getLevel().intValue() <= Level.INFO.intValue());

	}

	public static boolean isWarning(Logger log) {
		return (log.getLevel().intValue() <= Level.WARNING.intValue());

	}

	public static boolean isOff(Logger log) {
		return (log.getLevel().intValue() <= Level.OFF.intValue());

	}

}
