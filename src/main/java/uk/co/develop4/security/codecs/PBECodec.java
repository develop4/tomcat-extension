/* 
 * =============================================================================
 * 
 *  Copyright (c) 2014, The Develop4 Technologies Ltd (http://www.develop4.co.uk)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * =============================================================================
 */
package uk.co.develop4.security.codecs;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jasypt.encryption.StringEncryptor;
import org.jasypt.intf.service.JasyptStatelessService;

import uk.co.develop4.security.ConfigurationException;
import uk.co.develop4.security.utils.PropertyNaming;

/**
 * 
 * @author wtimpany
 */
public class PBECodec extends BaseCodec implements Codec, StringEncryptor {
    
	private final static Logger logger = Logger.getLogger(PBECodec.class.getName());

    private final String DEFAULT_DESCRIPTION 				= "PBE codec";
    private final String DEFAULT_NAMESPACE 					= "pbe://";
    private final String DEFAULT_PASSPHRASE 				= "446576656C6F7034546563686E6F6C6F67696573";
    private final String DEFAULT_PROVIDER_NAME 				= "BC";
    private final String DEFAULT_ALGORITHM_NAME 			= "PBEWITHSHA256AND256BITAES-CBC-BC";
    private final String DEFAULT_PROVIDER_CLASS_NAME 		= "org.bouncycastle.jce.provider.BouncyCastleProvider";
    private final String DEFAULT_OBTENTION_ITERATIONS 		= "50000";
    private final String DEFAULT_SALT_GENERATOR_CLASS_NAME 	= null;
    private final String DEFAULT_STRING_OUTPUT_TYPE 		= "hexadecimal";
    
    private String passphrase;
    private String providerName;
    private String providerClassName;
    private String algorithimName;
    private String saltGeneratorClassName;
    private String obtentionIterations;
    private String stringOutputType;
        
    public Map<String,Set<String>> getRequiredParameters() {
    	Map<String,Set<String>> requiredParams = new HashMap<String,Set<String>>();
    	Set<String> encodeParams = new HashSet<String>() ;
    	Set<String> decodeParams = new HashSet<String>()  ;
    	requiredParams.put("encode", encodeParams);
    	requiredParams.put("decode", decodeParams);
    	return requiredParams;
    }
    
    public Map<String,Set<String>> getOptionalParameters() {
    	Map<String,Set<String>> optionalParams = new HashMap<String,Set<String>>();
    	Set<String> encodeParams = new HashSet<String>(Arrays.asList(
    			PropertyNaming.PROP_PROVIDER_NAME.toString(),
    			PropertyNaming.PROP_ALGORITHM_NAME.toString(),
    			PropertyNaming.PROP_OBTENTION_ITERATIONS.toString(),
    			PropertyNaming.PROP_STRING_OUTPUT_TYPE.toString(),
    			PropertyNaming.PROP_LOGGING.toString()
    			)) ;
    	Set<String> decodeParams = new HashSet<String>(Arrays.asList(
    			PropertyNaming.PROP_PROVIDER_NAME.toString(),
    			PropertyNaming.PROP_ALGORITHM_NAME.toString(),
    			PropertyNaming.PROP_OBTENTION_ITERATIONS.toString(),
    			PropertyNaming.PROP_STRING_OUTPUT_TYPE.toString(),
    			PropertyNaming.PROP_LOGGING.toString()
    			)) ;
    	optionalParams.put("encode", encodeParams);
    	optionalParams.put("decode", decodeParams);
    	return optionalParams;
    }
    
	public PBECodec() {
	}
	
	@Override
	public void init(final Properties props) throws ConfigurationException  {
		try {
			setLoggerLevel(logger, props.getProperty(PropertyNaming.PROP_LOGGING.toString()));
			
			setPassphrase(props.getProperty(PropertyNaming.PROP_PASSPHRASE.toString(), DEFAULT_PASSPHRASE));			
			setNamespace(new Namespace(props.getProperty(PropertyNaming.PROP_NAMESPACE.toString(), DEFAULT_NAMESPACE)));
			setDescription(props.getProperty(PropertyNaming.PROP_DESCRIPTION.toString(), DEFAULT_DESCRIPTION));		
			setProviderName(props.getProperty(PropertyNaming.PROP_PROVIDER_NAME.toString(), DEFAULT_PROVIDER_NAME));
			setProviderClassName(props.getProperty(PropertyNaming.PROP_PROVIDER_CLASS_NAME.toString(), DEFAULT_PROVIDER_CLASS_NAME));
			setAlgorithimName(props.getProperty(PropertyNaming.PROP_ALGORITHM_NAME.toString(), DEFAULT_ALGORITHM_NAME));
			setObtentionIterations(props.getProperty(PropertyNaming.PROP_OBTENTION_ITERATIONS.toString(), DEFAULT_OBTENTION_ITERATIONS));
			setStringOutputType(props.getProperty(PropertyNaming.PROP_STRING_OUTPUT_TYPE.toString(), DEFAULT_STRING_OUTPUT_TYPE));
			setSaltGeneratorClassName(props.getProperty(PropertyNaming.PROP_SALT_GENERATOR_CLASS_NAME.toString(), DEFAULT_SALT_GENERATOR_CLASS_NAME));
		} catch (Exception ex) {
			logger.log(Level.SEVERE, "Failed to initialized Codec: {0}", getNamespace());
			throw new ConfigurationException(ex.fillInStackTrace());
		}
	}
	
	@Override
	public String encrypt(final String cleartext) {
		if (cleartext == null) {
			return cleartext;
		}
		final JasyptStatelessService service = new JasyptStatelessService();
		return addNamespacePrefix(service.encrypt(
        		cleartext, 
                getPassphrase(),
                null,
                null,
                getAlgorithimName(),
                null,
                null,
                getObtentionIterations(),
                null,
                null,
                getSaltGeneratorClassName(),
                null,
                null,
                getProviderName(),
                null,
                null,
                getProviderClassName(),
                null,
                null,
                getStringOutputType(),
                null,
                null));
	}

	@Override
	public String decrypt(final String cyphertext) {
		if (cyphertext == null) {
			return cyphertext;
		}
		try {	
            final JasyptStatelessService service = new JasyptStatelessService();
			return service.decrypt(
            		removeNamespacePrefix(cyphertext), 
                    getPassphrase(),
                    null,
                    null,
                    getAlgorithimName(),
                    null,
                    null,
                    getObtentionIterations(),
                    null,
                    null,
                    getSaltGeneratorClassName(),
                    null,
                    null,
                    getProviderName(),
                    null,
                    null,
                    getProviderClassName(),
                    null,
                    null,
                    getStringOutputType(),
                    null,
                    null);
		} catch (Exception ex) { 
			ex.printStackTrace(); 
		}
		return cyphertext;	
	}
	

	public String getPassphrase() {
		return this.passphrase;
	}

	public void setPassphrase(final String passphrase) {
		this.passphrase = passphrase;
	}

	public String getProviderName() {
		return this.providerName;
	}

	public void setProviderName(final String providerName) {
		this.providerName = providerName;
	}

	public String getAlgorithimName() {
		return this.algorithimName;
	}

	public void setAlgorithimName(final String algorithimName) {
		this.algorithimName = algorithimName;
	}

	public String getSaltGeneratorClassName() {
		return this.saltGeneratorClassName;
	}

	public void setSaltGeneratorClassName(final String saltGeneratorClassName) {
		this.saltGeneratorClassName = saltGeneratorClassName;
	}

	public String getObtentionIterations() {
		return this.obtentionIterations;
	}

	public void setObtentionIterations(final String obtentionIterations) {
		this.obtentionIterations = obtentionIterations;
	}

	public String getStringOutputType() {
		return this.stringOutputType;
	}

	public void setStringOutputType(final String stringOutputType) {
		this.stringOutputType = stringOutputType;
	}
	
	public String getProviderClassName() {
		return this.providerClassName;
	}

	public void setProviderClassName(String providerClassName) {
		this.providerClassName = providerClassName;
	}
	
	public void setLoggerLevel(Level level) {
		logger.setLevel(level);
	}

}