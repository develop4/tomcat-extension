package uk.co.develop4.security;

import java.util.Properties;

public interface InitializableObject {
	public void init(Properties props) throws ConfigurationException;
}