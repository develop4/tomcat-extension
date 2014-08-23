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
	private static Log log = LogFactory.getLog(PropertyDecoderServiceTest.class);

	
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
						
			//URL appUrl = getClass().getResource("/restricted/properties/application.properties");
			//Path appPath = Paths.get(appUrl.toURI());
			//System.setProperty(PropertyDecoderService.PROPERTIES_PROP, appPath.toString());

			//URL secUrl = getClass().getResource("/restricted/keystore/secure.file");
			//Path secPath = Paths.get(secUrl.toURI());
			//System.setProperty(PropertyDecoderService.PASSPHRASE_PROP, secPath.toString());
			
			System.setProperty("catalina.base", configPath.getParent().getParent().getParent().toString());
			
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
