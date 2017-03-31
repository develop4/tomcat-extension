package uk.co.develop4.security.codecs;

import static org.junit.Assert.assertEquals;

import java.util.Properties;

import org.junit.Test;

import uk.co.develop4.security.test.BaseTest;

public class TestPBECodec extends BaseTest {

	@Test
	public void performValidEncryptAndDecrypt() throws Exception {
		String cleartext = "XXXxxxTESTxxxXXX";
		String passphrase = "Develop4Technologies";
		
		Properties properties = new Properties();
		properties.put("logging", "FINEST");
		properties.put("passphrase", passphrase);
		properties.put("namespace", "pbe://");
		
		Codec codec = CodecFactory.getCodec(PBECodec.class.getName(), properties);
		
		String cyphertextTemp = codec.encrypt(cleartext);
		String cleartextTemp = codec.decrypt(cyphertextTemp);
		
		assertEquals(cleartext, cleartextTemp);
	}
	
	@Test
	public void performValidDecryptFromFixedCyphertext() throws Exception {
		String cleartext = "XXXSecretPasswordPBEStrongXXX";
		String cyphertext = "pbe://D4D79C5C039D4B3C7841E03829711785B6D3CEF17643DB6B90409F664A557838E8C9D8EE749BB46057FBE370A53A467A";
		String passphrase = "Develop4Technologies";
		
		Properties properties = new Properties();
		properties.put("logging", "FINEST");
		properties.put("passphrase", passphrase);
		properties.put("namespace", "pbe://");
		
		Codec codec = CodecFactory.getCodec(PBECodec.class.getName(), properties);
		
		String cleartextTemp = codec.decrypt(cyphertext);
		
		assertEquals(cleartext, cleartextTemp);
	}

}
