package uk.co.develop4.security.codecs;

import static org.junit.Assert.assertEquals;

import java.util.Properties;

import org.junit.Test;

import uk.co.develop4.security.ConfigurationException;

public class TestNullCodec {

	@Test
    public void performValidEncryptAndDecrypt() throws Exception
    {
		String passphrase = "passphrase";
		Properties propeties = new Properties();
		
		NullCodec codec = new NullCodec();
		codec.init(passphrase, propeties);
		
		String secret = "XXXxxx TestValue xxxXXX";
		String cyphertext = codec.encrypt(secret);
		String cleartext = codec.decrypt(cyphertext);
		
		assertEquals("Secret equals Cleartext", secret, cleartext);
    }
	
	@Test
    public void initWithNullPassphraseDoesNotThrowException() throws Exception
    {
		NullCodec codec = new NullCodec();
		codec.init(null, new Properties());

    }
	
	@Test(expected=ConfigurationException.class) 
    public void initWithNullPropertiesThrowsException() throws Exception
    {
		NullCodec codec = new NullCodec();
		codec.init("Passphrase", null);
    }
}
