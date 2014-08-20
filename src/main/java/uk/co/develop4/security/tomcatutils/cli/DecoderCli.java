package uk.co.develop4.security.tomcatutils.cli;

import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import org.jasypt.commons.CommonUtils;

import uk.co.develop4.security.tomcat.PropertyDecoderService;
import uk.co.develop4.security.utils.decoders.PropertyNaming;

public final class DecoderCli {
	
	private static org.apache.juli.logging.Log log = org.apache.juli.logging.LogFactory.getLog(DecoderCli.class);

	private DecoderCli() {
    }
	
    public static void main(final String[] args) {
    	DecoderCli dcli = new DecoderCli();
    	dcli.run(args);
    }

    public void run(final String[] args) {

    	try {
    		// -- Convert input parameters into Properties file
    		final Set<String> argNames = new HashSet<String>();
    		for(PropertyNaming val : PropertyNaming.values()) {
    			argNames.add(val.toString());
    		}
    		
    		final Properties argumentValues = new Properties();
            for (int i = 0; i < args.length; i++) {
                final String key = CommonUtils.substringBefore(args[i], "=");
                final String value = CommonUtils.substringAfter(args[i], "=");
                if (CommonUtils.isEmpty(key) || CommonUtils.isEmpty(value)) {
                    throw new IllegalArgumentException("Bad argument: " + args[i]);
                }
                if (argNames.contains(key)) {
                    if (value.startsWith("\"") && value.endsWith("\"")) {
                    	System.setProperty(key, value.substring(1, value.length() - 1));
                    	argumentValues.setProperty(key, value.substring(1, value.length() - 1));
                    } else {
                    	System.setProperty(key, value);
                    	argumentValues.setProperty(key, value);
                    }
                } else {
                    throw new IllegalArgumentException("Bad argument: " + args[i]);
                }
            }
			
            if (argumentValues.getProperty(PropertyNaming.PROP_CONFIGURATION.toString()) != null) {
            	System.setProperty(
            			PropertyDecoderService.class.getName() + "." +PropertyNaming.PROP_CONFIGURATION.toString(),
            			argumentValues.getProperty(PropertyNaming.PROP_CONFIGURATION.toString()));
            }
            if (argumentValues.getProperty(PropertyNaming.PROP_PROPERTIES.toString()) != null) {
            	System.setProperty(
            			PropertyDecoderService.class.getName() + "." +PropertyNaming.PROP_PROPERTIES.toString(),
            			argumentValues.getProperty(PropertyNaming.PROP_PROPERTIES.toString()));
            }
            if (argumentValues.getProperty(PropertyNaming.PROP_PASSPHRASE.toString()) != null) {
            	System.setProperty(
            			PropertyDecoderService.class.getName() + "." + PropertyNaming.PROP_PASSPHRASE.toString(),
            			argumentValues.getProperty(PropertyNaming.PROP_PASSPHRASE.toString()));
            }
                        
    		PropertyDecoderService pds = new PropertyDecoderService();
    		
    		String namespaceKey = (String)System.getProperty(PropertyNaming.PROP_NAMESPACE.toString());
    		String value = (String)System.getProperty(PropertyNaming.PROP_INPUT.toString());
    		String coded = pds.encodePropertyValue(namespaceKey, value);
    		
    		log.info("Encrypted Value: " + coded);
    	} catch (Exception ex) {
    		ex.printStackTrace();
    	}
    }

}
