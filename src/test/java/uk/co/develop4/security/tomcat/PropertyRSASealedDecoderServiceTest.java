package uk.co.develop4.security.tomcat;

import static org.junit.Assert.assertEquals;

import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.Test;

/**
 * Unit test for simple configuration
 */
public class PropertyRSASealedDecoderServiceTest
{
	
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
	@Test
    public void basicTest()
    {
		try {			
			String testValue = "XXXxxxTESTxxxXXX";
			
			URL configUrl = getClass().getResource("/restricted/settings/decoder.properties");
			Path configPath = Paths.get(configUrl.toURI());
			System.setProperty(PropertyDecoderService.CONFIGURATION_PROP, configPath.toString());
			System.setProperty("catalina.base", configPath.getParent().getParent().getParent().toString());
			
			PropertyDecoderService pds = new PropertyDecoderService();
			
			String coded = pds.encodePropertyValue("rsa:sealed//", testValue, "LabelForSealedValue");
			String decoded = pds.decodePropertyValue("rsa:sealed//", coded);
			
			System.out.println("Encoded String Length: " + coded.length());
			assertEquals(testValue, decoded);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
    }

}
