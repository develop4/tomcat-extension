package uk.co.develop4.security.codecs;

import static org.junit.Assert.*;

import java.util.Optional;
import java.util.Properties;

import org.junit.Test;

public class TestCodecRegistry {

	@Test
	public void createRegistry() throws Exception{
		
		String value = "hex://";
		String data  = "hex://5468697320697320612074657374";
		
		CodecRegistry codecRegistry = new CodecRegistry();
		
		Optional<Namespace> namespace = Namespace.extractNamespace(data);

		assertNotNull(namespace.get());
		assertEquals(value, namespace.get().getValue());
				
		Codec codecIn = new HexCodec();
		Properties props = new Properties();
		props.setProperty("description", "changed me");
		codecIn.init(props);
		
		codecRegistry.put(codecIn);
		
		Optional<Codec> codecOut1 = codecRegistry.get(codecIn.getNamespace());
		
		assertEquals(codecIn, codecOut1.get());

	}

}
