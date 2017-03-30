package uk.co.develop4.security.test;

import java.security.Security;
import java.util.logging.Logger;

public class BaseTest {
	
	private final static Logger logger = Logger.getLogger(BaseTest.class.getName());


	public BaseTest(){
		initialiseLogging();
		initialiseUnlimitedStrengthEncryption();
	}
	
	private void initialiseLogging() {
		LoggingConfig loggingConfig = new LoggingConfig();
	}

	
	private void initialiseUnlimitedStrengthEncryption() {
		try {
			if (Security.getProvider("BC") == null) {
	            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	        }
		} catch (Exception ex) {
			logger.warning(ex.getMessage());
		}
	}
}
