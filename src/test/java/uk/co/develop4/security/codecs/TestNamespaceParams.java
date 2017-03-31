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

import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import uk.co.develop4.security.test.BaseTest;

@RunWith(Parameterized.class)
public class TestNamespaceParams  extends BaseTest{
	
	private String datum;
	private Namespace expected;

	@Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {     
                 { "hex://xxxxxx", 		new Namespace("hex://") }, 
                 { "null://yyyyy", 		new Namespace("null://") }, 
                 { "rsa:key1//xxxxxx", 	new Namespace("rsa:key1//") },  
                 { "rsa:key2//yyyyyy", 	new Namespace("rsa:key2//") },
                 { "r*sa:key2//yyyyyy", null },
                 { "nonamespace", 		null },
                 { "nonam//espace", 	null },
                 { "//:invalid:namespace//ddsdsdsdsd", null}
           });
    }

    public TestNamespaceParams(String datum, Namespace expected) {
        this.datum = datum;
        this.expected = expected;
    }

    @Test
    public void test() {
        assertEquals("Extracted namespaces should match", expected, Namespace.valueOf(datum).orElse(null));
    }

}
