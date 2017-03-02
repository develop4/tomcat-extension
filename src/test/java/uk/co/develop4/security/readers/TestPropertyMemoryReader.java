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

import static org.junit.Assert.assertEquals;

import java.util.Properties;

import org.junit.Test;

public class TestPropertyMemoryReader {

	@Test
	public void testCreateAndRead() {
		PropertyMemoryReader propertyMemoryReader = new PropertyMemoryReader();
		propertyMemoryReader.init(new Properties());
		
		Properties props = propertyMemoryReader.read();
		
		assertEquals("Hardcoded properties match", "TEST_ONE", props.get("property.memory.reader.test1"));
		assertEquals("Hardcoded properties match", "TEST_TWO", props.get("property.memory.reader.test2"));
	}
}