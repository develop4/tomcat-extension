package uk.co.develop4.security.codecs;

import static org.junit.Assert.assertEquals;

import java.util.Properties;

import org.junit.Test;

import uk.co.develop4.security.test.BaseTest;

public class TestRSACodec extends BaseTest {

	@Test
	public void performValidEncryptAndDecrypt() throws Exception {
		String cleartext = "XXXxxxTESTxxxXXX";

		String privateKeyFile = getClass().getResource("/restricted/keystore/privateOne.pem").getPath();
		String publicKeyFile  = getClass().getResource("/restricted/keystore/publicOne.pem").getPath();

		Properties properties = new Properties();
		properties.put("logging", "FINEST");
		properties.put("passphrase", "CHANGEIT");
		properties.put("namespace", "rsa:one//");
		properties.put("privateKeyFile", privateKeyFile);
		properties.put("publicKeyFile",  publicKeyFile);
		
		Codec codec = CodecFactory.getCodec(RSACodec.class.getName(), properties);
		
		String cyphertextTemp = codec.encrypt(cleartext);
		String cleartextTemp = codec.decrypt(cyphertextTemp);
		
		assertEquals(cleartext, cleartextTemp);
	}
	
	@Test
	public void performValidDecryptFromFixedCyphertext() throws Exception {
		String cleartext = "XXXxxxTESTxxxXXX";
		String cyphertext = "rsa:one//5282af6780070c13327cecc766cfe7530eb275ed0d7e3ccf5e0001c0a6685bcaa43a13126e5921da0e58027cfb3c42da658dbb2e94932db53ac30a5a305e7cbb3586bba0463b1b20e0eb3735457710b42773d30011154059c03ac93681ffb86de3d448d3159a1bdff6c5de7b1ae4c951dd7508ea3c7d883c0853bb61a956be3b37600f07bc8d66f6e9b7aec7aaa853a06ffd4e8fec2d9ae954ec4d193405e40a2075518759a1ba07429b4e02b81b55a5074e33f26fe31c22a485b5d7e819edb018332f8308a2fa392063899fef752081ee03147e1a7a075325676eb2e7b898c67d06d6a3db6409f2018f241467d8632af7258e4bb82e03c2cf320f17e53371b4";

		String privateKeyFile = getClass().getResource("/restricted/keystore/privateOne.pem").getPath();
		String publicKeyFile  = getClass().getResource("/restricted/keystore/publicOne.pem").getPath();

		Properties properties = new Properties();
		properties.put("logging", "FINEST");
		properties.put("passphrase", "CHANGEIT");
		properties.put("namespace", "rsa:one//");
		properties.put("privateKeyFile", privateKeyFile);
		properties.put("publicKeyFile",  publicKeyFile);
		
		Codec codec = CodecFactory.getCodec(RSACodec.class.getName(), properties);
		
		String cleartextTemp = codec.decrypt(cyphertext);
		
		assertEquals(cleartext, cleartextTemp);
	}

}
