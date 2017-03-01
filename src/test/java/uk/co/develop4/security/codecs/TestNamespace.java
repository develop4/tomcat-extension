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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Optional;

import org.junit.Test;

public class TestNamespace {

	@Test
	public void extractNamespace() throws Exception{
		String VALUE   	= "hex://";
		String data  			= "hex://aaaaaaaa";
		
		Optional<Namespace> namespace = Namespace.extractNamespace(data);

		assertNotNull(namespace.get());
		assertEquals(VALUE, namespace.get().getValue());
	}
	
	@Test
	public void createNamespace() throws Exception {
		String NAMESPACE = "test:one://";
		
		Namespace namespace = new Namespace(NAMESPACE);
		
		assertEquals(namespace.getValue(), NAMESPACE);
	}
	
	@Test
	public void compareTwoLikeNamespace() throws Exception {
		String NAMESPACE = "test:one://";
		
		Namespace namespace1 = new Namespace(NAMESPACE);
		Namespace namespace2 = new Namespace(NAMESPACE);
		
		assertEquals("The two mamespaces should show as being equal", namespace1, namespace2);
	}
	
	@Test
	public void compareTwoDifferentNamespace() throws Exception {
		String NAMESPACE1 = "test:one://";
		String NAMESPACE2 = "test:teo://";

		Namespace namespace1 = new Namespace(NAMESPACE1);
		Namespace namespace2 = new Namespace(NAMESPACE2);
		
		assertNotEquals("The two mamespaces should show as being unequal", namespace1, namespace2);
	}
	
	@Test
	public void addPrefixToValue() throws Exception {
		String NAMESPACE = "test:one://";
		String DATA = "XXXXXXXXXX";
		String NAMESPACED = NAMESPACE + DATA;
		
		Namespace namespace = new Namespace(NAMESPACE);
		String namespaced = namespace.addNamespacePrefix(DATA);
		
		assertEquals("Namespace string should equal precalculated version", NAMESPACED, namespaced);
	}
	
	@Test
	public void removePrefixFromValue() throws Exception {
		String NAMESPACE = "test:one://";
		String DATA = "XXXXXXXXXX";
		String NAMESPACED = "test:one://XXXXXXXXXX";
		
		Namespace namespace = new Namespace(NAMESPACE);
		String data = namespace.removeNamespacePrefix(NAMESPACED);
		
		assertEquals("Namespace string should equal precalculated version", DATA, data);
	}
	
	@Test
	public void isValueInNamespace() throws Exception {
		String NAMESPACE = "test:one://";
		String NAMESPACED = "test:one://XXXXXXXXXX";
		
		Namespace namespace = new Namespace(NAMESPACE);
		boolean check = namespace.isValueInNamespace(NAMESPACED);
		
		assertTrue("Value starts with namespace", check);
	}

}
