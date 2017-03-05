package uk.co.develop4.security.test;

import java.io.InputStream;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public class LoggingConfig {

	public LoggingConfig() {
	        try {
	            
	            final LogManager logManager = LogManager.getLogManager();
	            try (final InputStream is = getClass().getResourceAsStream("/logging.properties")) {
	                logManager.readConfiguration(is);
	            }
	            /*
	            // Programmatic configuration
	            System.setProperty("java.util.logging.SimpleFormatter.format","%1$tY-%1$tm-%1$td %1$tH:%1$tM:%1$tS.%1$tL %4$-7s [%3$s] (%2$s) %5$s %6$s%n");

	            final ConsoleHandler consoleHandler = new ConsoleHandler();
	            consoleHandler.setLevel(Level.FINEST);
	            consoleHandler.setFormatter(new SimpleFormatter());

	            final Logger app = Logger.getLogger("uk.co.develop4.security");
	            app.setLevel(Level.FINEST);
	            app.addHandler(consoleHandler);
	            */
	        } catch (Exception e) {
	            e.printStackTrace();
	        }
	}

}
