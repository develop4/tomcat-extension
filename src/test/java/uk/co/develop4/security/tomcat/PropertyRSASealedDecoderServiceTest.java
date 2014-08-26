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
			
			String configPath = getClass().getResource("/restricted/settings/decoder.properties").getPath();
			System.setProperty(PropertyDecoderService.CONFIGURATION_PROP, configPath);
			
			String catalinaBase = getClass().getResource("/").getPath();
			System.setProperty("catalina.base", catalinaBase);
			
			PropertyDecoderService pds = new PropertyDecoderService();
			
			String coded = pds.encodePropertyValue("rsa:sealed//", testValue, "LabelForSealedValue");
			String decoded = pds.decodePropertyValue("rsa:sealed//", coded);
			
			assertEquals(testValue, decoded);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
    }

}
