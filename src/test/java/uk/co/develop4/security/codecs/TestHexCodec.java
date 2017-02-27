package uk.co.develop4.security.codecs;

import static org.junit.Assert.assertEquals;

import java.util.Properties;

import org.junit.Test;

import uk.co.develop4.security.ConfigurationException;

public class TestHexCodec {

	@Test
	public void validEncryptAndDecryptCycle() throws Exception {
		String passphrase = "passphrase";
		Properties propeties = new Properties();

		HexCodec codec = new HexCodec();
		codec.init(passphrase, propeties);

		String secret = "XXXxxx TestValue xxxXXX";
		String cyphertext = codec.encrypt(secret);
		String cleartext = codec.decrypt(cyphertext);

		assertEquals(secret, cleartext);
	}

	@Test
	public void initWithNullPassphraseDoesNotThrowException() throws Exception {
		String passphrase = null;
		Properties propeties = new Properties();

		HexCodec codec = new HexCodec();
		codec.init(passphrase, propeties);
	}

	@Test(expected = ConfigurationException.class)
	public void initWithNullPropertiesThrowsException() throws Exception {
		String passphrase = "passphrase";
		Properties propeties = null;

		HexCodec codec = new HexCodec();
		codec.init(passphrase, propeties);
	}
}
