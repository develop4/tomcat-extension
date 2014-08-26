package uk.co.develop4.security.tomcat;

import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.junit.Test;

import uk.co.develop4.security.tomcat.PropertyDecoderService;

/**
 * Unit test for simple configuration
 */
public class PropertyDecoderServiceTest 
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
			URL configUrl = getClass().getResource("/restricted/settings/decoder.properties");
			Path configPath = Paths.get(configUrl.toURI());
			System.setProperty(PropertyDecoderService.CONFIGURATION_PROP, configPath.toString());
						
			String catalinaBase = getClass().getResource("/").getPath();
			System.setProperty("catalina.base", catalinaBase);
			
			System.setProperty("org.apache.tomcat.util.digester.PROPERTY_SOURCE","uk.co.develop4.security.tomcat.PropertyDecoderService");
						
			PropertyDecoderService service = new PropertyDecoderService();

			Properties props = new Properties();
	        URL url = getClass().getResource("/context.properties");
	        props.load(url.openStream());
	        for(Object key: props.keySet()) {
	        	String myKey = key.toString();
	        	service.getProperty(props.getProperty(myKey).replaceAll("[${}]", ""));
	        }
						
		} catch (Exception e) {
			e.printStackTrace();
		}
    }

}
