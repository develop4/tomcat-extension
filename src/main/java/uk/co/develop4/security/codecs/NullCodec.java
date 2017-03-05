package uk.co.develop4.security.codecs;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jasypt.encryption.StringEncryptor;

import uk.co.develop4.security.ConfigurationException;

public class NullCodec extends BaseCodec implements Codec, StringEncryptor {
	    
		private final static Logger logger = Logger.getLogger(NullCodec.class.getName());

	    private final String DEFAULT_NAMESPACE 		= "null://";
	    private final String DEFAULT_DESCRIPTION 	= "Null codec";
	    
		public Map<String,Set<String>> getRequiredParameters() {
	    	Map<String,Set<String>> requiredParams = new HashMap<String,Set<String>>();
	    	Set<String> encodeParams = new HashSet<String>();
	    	Set<String> decodeParams = new HashSet<String>();
	    	requiredParams.put("encode", encodeParams);
	    	requiredParams.put("decode", decodeParams);
	    	return requiredParams;
	    }
	    
	    public Map<String,Set<String>> getOptionalParameters() {
	    	Map<String,Set<String>> optionalParams = new HashMap<String,Set<String>>();
	    	Set<String> encodeParams = new HashSet<String>() ;
	    	Set<String> decodeParams = new HashSet<String>() ;
	    	optionalParams.put("encode", encodeParams);
	    	optionalParams.put("decode", decodeParams);
	    	return optionalParams;
	    }
	    
		public NullCodec() {
		}
		
		@Override
		public void init(Properties props) throws ConfigurationException {
			try {
				setNamespace(new Namespace(DEFAULT_NAMESPACE));
				setDescription(DEFAULT_DESCRIPTION);
			} catch (Exception ex) {
				logger.log(Level.SEVERE, "Failed to initialized Codec: {0}", getNamespace());
				throw new ConfigurationException(ex.fillInStackTrace());
			}
		}
		
		@Override
		public String encrypt(final String cleartext) {
			return cleartext;
		}

		@Override
		public String decrypt(final String cyphertext)  {
			return cyphertext;
		}
		
		public void setLoggerLevel(Level level) {
			logger.setLevel(level);
		}

}
