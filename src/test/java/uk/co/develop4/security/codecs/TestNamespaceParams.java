package uk.co.develop4.security.codecs;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class TestNamespaceParams {
	
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
        assertEquals("Extracted namespaces should match", expected, Namespace.extractNamespace(datum).orElse(null));
    }

}
