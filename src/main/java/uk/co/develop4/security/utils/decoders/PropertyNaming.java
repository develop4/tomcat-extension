/* 
 * =============================================================================
 * 
 *  Copyright (c) 2014, The Develop4 Technologies Ltd (http://www.develop4.co.uk)
 *
 * Licensed under the Apache License, Version 2.0 (the "License")),
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
package uk.co.develop4.security.utils.decoders;
/**
 * 
 * @author williamtimpany
 *
 */
public enum PropertyNaming {

	PROP_NAMESPACE("namespace"),
	PROP_PASSPHRASE("passphrase"),
	PROP_PROVIDER_NAME("providerName"),
	PROP_PROVIDER_CLASS_NAME("providerClassName"),
	PROP_ALGORITHM_NAME("algorithmName"),
	PROP_OBTENTION_ITERATIONS("obtentionIterations"),
	PROP_SALT_GENERATOR_CLASS_NAME("saltGeneratorClassName"),
	PROP_STRING_OUTPUT_TYPE("stringOutputType"),
	PROP_KEYSTORE_TYPE("keyStoreType"),
	PROP_KEYSTORE_PATH("keyStorePath"),
	PROP_PRIVATE_KEYFILE("privateKeyFile"),
	PROP_PUBLIC_KEYFILE("publicKeyFile"),
	PROP_DEBUG("debug"),
	PROP_CONSOLE_TIMEOUT("consoleTimeout"),
	PROP_CONFIGURATION("configuration"),
	PROP_PROPERTIES("properties"),
	PROP_DECODER("decoder"),
	PROP_INPUT("input"),
	PROP_BASE64("base64://"),
	PROP_HEX("hex://");
	
	private String value;

    private PropertyNaming(String value) {
            this.value = value;
    }

    public String toString(){
       return value;
    }
}
