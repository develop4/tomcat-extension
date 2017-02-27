package uk.co.develop4.security.tomcat;

import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

import org.junit.Test;

import uk.co.develop4.security.tomcat.PropertyCodecService;

/**
 * Unit test for simple configuration
 */
public class TestPropertyCodecService {

	/**
	 * Create the test case
	 */
	@Test
	public void initializeServiceFromPropertiesFile() throws Exception {
		URL configUrl = getClass().getResource("/restricted/settings/codec.properties");
		Path configPath = Paths.get(configUrl.toURI());
		System.setProperty(PropertyCodecService.CONFIGURATION_PROP, configPath.toString());

		String catalinaBase = getClass().getResource("/").getPath();
		if (catalinaBase.endsWith("/")) {
			catalinaBase = catalinaBase.substring(0, catalinaBase.length() - 1);
		}
		System.setProperty("catalina.base", catalinaBase);

		System.setProperty("org.apache.tomcat.util.digester.PROPERTY_SOURCE",
				"uk.co.develop4.security.tomcat.PropertyCodecService");

		PropertyCodecService service = new PropertyCodecService();

		Properties props = new Properties();
		URL url = getClass().getResource("/context.properties");
		props.load(url.openStream());
		for (Object key : props.keySet()) {
			String myKey = key.toString();
			service.getProperty(props.getProperty(myKey).replaceAll("[${}]", ""));
		}

	}

}
