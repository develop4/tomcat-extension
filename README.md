tomcat-extension
================

Digester Extensions for Tomcat 7

Security extensions to allow the encryption of settings in the Tomcat 7 configuration files.  

This extra functionality should keep every auditor in the world happy, as well as dev/ops. 

This new digester allows the separation of Application Credentials and other sensitive information
from the main tomcat configuration files.   The digester configuration, application credentials and passphrases
can all be stored in separate areas under heightened security control.   The plug-able decryption modules allow
for different decryption methods to be employed.  The cyphertext is passed to the appropriate module for decryption
based on the namespace prefix of the cyphertext.   Each Decoder Module is associated with a namespace prefix, this
namespace prefix is returned from the "getNamespace()" method on the Module.
 
The Decoders default behavior should allow them to work without additional configuration. If the Decoder does require additional configuration
then parameters can be passed from the decoder.properties file.

At tomcat server startup the decryption modules are initialized. Then as tomcat reads the server configuration files the custom 
digester will decrypt the properties and perform variable substitution of the matched values.

**Sample: catalina.properties**
Modify the catalina properties file to plug-in the new custom digester and point to its configuration file.
```
org.apache.tomcat.util.digester.PROPERTY_SOURCE=com.develop4.security.tomcat.PropertyDecoderService
com.develop4.security.tomcat.PropertyDecoderService.configuration=${catalina.base}/restricted/settings/decoder.properties
```

**Sample: decoder.properties**
This file contains the list of decoders in order or precedence that will be used for decrypting the values which have a prefix that matches
the decoder namespace.   Specific values can be passed as properties to each decoder to override the default values, create another property 
prefixed with the decoder class name.  e.g. 'com.develop4.security.utils.decoders.NullDecoder.debug=true'
```
com.develop4.security.tomcat.PropertyDecoderService.passphrase=${catalina.base}/restricted/keystore/secure.file
com.develop4.security.tomcat.PropertyDecoderService.properties=${catalina.base}/restricted/properties/application.properties
com.develop4.security.tomcat.PropertyDecoderService.decoder.1=com.develop4.security.utils.decoders.NullDecoder
com.develop4.security.tomcat.PropertyDecoderService.decoder.1.debug=true
com.develop4.security.tomcat.PropertyDecoderService.decoder.2=com.develop4.security.utils.decoders.Base64Decoder
com.develop4.security.tomcat.PropertyDecoderService.decoder.3=com.develop4.security.utils.decoders.HexDecoder
com.develop4.security.tomcat.PropertyDecoderService.decoder.4=com.develop4.security.utils.decoders.PBEDecoder
com.develop4.security.tomcat.PropertyDecoderService.decoder.5=com.develop4.security.utils.decoders.RSADecoder
com.develop4.security.tomcat.PropertyDecoderService.decoder.6.privateKeyFile=file://${catalina.base}/restricted/keystore/privateKeyOne.pem
com.develop4.security.tomcat.PropertyDecoderService.decoder.6=com.develop4.security.utils.decoders.RSADecoder
# Create new decoder with seperate namespace to handle another private key
com.develop4.security.tomcat.PropertyDecoderService.decoder.6.privateKeyFile=file://${catalina.base}/restricted/keystore/privateKeyTwo.pem
com.develop4.security.tomcat.PropertyDecoderService.decoder.6.namespace=rsa:key2//
```

**Sample: secure.file (Encrypted Master Key)**
This file contains the Default Master Key that will be used to decrypt all the password values.  Single value on one line that is hex encoded. 
This is the default key passed to all the decryption modules, but this can be overridden by property values passed to the modules.
```
hex://33306636336330322d626539342d343065392d623034302d646661623033333661643930
```

**Sample: application.properties**
This file contains all the encrypted passwords/values that will be decrypted and replace the placeholder values in the tomcat configuration files at runtime.
The file is a simple name/value pair property file.
```
my.test.property.one=null://123456789asdf
my.test.property.two=base64://RGV2ZWxvcDRQcm9wZXJ0aWVz
my.test.property.three=hex://446576656c6f7034546563686e6f6c6f67696573
my.test.property.four=pbe://380D5EB7A79BDD4B73B27F7BD22E0F232D4104D8C6C90033F07D680AD7876E62CF905F0D189628CEDF24CADEA388BDCF
rsa.encrypted.test1=rsa://46f39ee604944a253ed298728c422ca1931f1eb0d433a450e941735f6b335b...c911
rsa.encrypted.test2=rsa:key2//46f39ee604944a253ed298728c422ca1931f1eb0d433a450e941735f6b...4d82
tomcat.conf.groupdirectory.user=pbe://B18B73A3C81408DD637BBF4CDC884F1BB1E24845F31EC3237A165BB8568EB0F5
tomcat.conf.groupdirectory.password=pbe://1E5452D5088A87251182917E79056B45216B67277BFFD25DA438D3BE153C29C8
tomcat.conf.server.jdbc.Secure.trustStorePassword=pbe://B6F6365F73028930C4DE748447725E58470E48FA3B6CE33105CECAE0F3C6EB29
tomcat.conf.server.jdbc.Secure.keyStorePassword=pbe://AA605E3FAE18F08F75FDA06D48CC1E4298841B586FE3D5F630D8687AD836AC18
```

**Sample: context.xml**
The properties will be replaced in all Tomcat configuration files.  
e.g. for the `context.xml` file add the placeholders for the LDAP User Account Settings (see the attached file for an example):
```
<Context>
    <Environment name="GroupDirectory/LDAPUser" value="${tomcat.conf.groupdirectory.ldap.user}"     override="false" type="java.lang.String"/>
    <Environment name="GroupDirectory/LDAPPass" value="${tomcat.conf.groupdirectory.ldap.password}" override="false" type="java.lang.String"/>
</Context>
```

**Sample: server.xml**
Add the placeholders for the Database User Account Settings, or other properties that you do not want to be visible as plain text.  e.g. Replace all the Usernames and Passwords in the `server.xml` file with the 
placeholder values stored in the `application.properties` file.
```
<Resource name="jdbc/Reporter"
    connectionPoolName="Reporter"
    url="jdbc:oracle:thin:@lnnart1.uk.com:9801:DONTLOOK1"
    user="${tomcat.conf.server.jdbc.Reporter.user}"
    password="${tomcat.conf.server.jdbc.Reporter.password}"
/>
<Resource name="jdbc/WalletUser" 
    connectionPoolName="WalletUser"
    description="Oracle Connection using Certificate Based Authentication"
    auth="Container" 
    type="oracle.ucp.jdbc.PoolDataSource" 
    factory="oracle.ucp.jdbc.PoolDataSourceImpl"
    connectionFactoryClassName="oracle.jdbc.pool.OracleDataSource"
    url="jdbc:oracle:thin:@(DESCRIPTION=(ADDRESS=(PROTOCOL=TCPS)(HOST=lnnart1.db.com)(PORT=9802))(CONNECT_DATA=(SERVER=DEDICATED)(SERVICE_NAME=LNNART1.UK.COM)))"
    connectionProperties="(oracle.net.ssl_version=3.0,
oracle.net.ssl_client_authentication=true,
oracle.net.authentication_services=(TCPS),
javax.net.ssl.trustStore=${catalina.base}/restricted/wallets/nar_ssl_user/truststore.jks,
javax.net.ssl.trustStoreType=JKS,
javax.net.ssl.trustStorePassword=${tomcat.conf.server.jdbc.Secure.trustStorePassword},
javax.net.ssl.keyStore=${catalina.base}/restricted/wallets/nar_ssl_user/nar_ssl_user.jks,
javax.net.ssl.keyStoreType=JKS,
javax.net.ssl.keyStorePassword=${tomcat.conf.server.jdbc.Secure.keyStorePassword})"		
	/>
```

**Provided Decoders**

The following Decoders are provided as examples in the 'com.develop4.security.utils.decoders package'.

| Decoder | Prefix | Functionality
| ------- | ------ | -------------
| NullDecoder |  null:// | Pass through, just returns the value without change.  For testing.
| HexDecoder | hex:// | Hexadecimal decoder converts to/from Hex values
| Base64Decoder | base64:// | Base64 decoder converts to/from Base64 values
| PBEDecoder | pbe:// | Password Based Encryption : using Algorithm PBEWITHSHA256AND256BITAES-CBC-BC from Bouncy Castle : SHA256 hash, AES with 256 bit key, Cipher-Block Chaining 
| RSADecoder | rsa:// | RSA Public Key Based Encryption : using RSA Public Key to encrypt the data and RSA Private Key to decrypt the data. 


**Note**
The following jars were added to the Tomcat Lib directory to support the Decoding/Connection Pool/Decryption.

```
Oracle [ http://www.oracle.com/technetwork/database/features/jdbc/index-091264.html ]
   ucp-11.2.0.2.jar       * Universal Connection Pool from Oracle
   ojdbc6_11.2.0.2.0.jar  * jdbc connection to Oracle
   oraclepki-11.2.0.2.jar * required for TCPS connection to Oracle
   osdt_cert-11.2.0.2.jar * required for TCPS connection to Oracle
   osdt_core-11.2.0.2.jar * required for TCPS connection to Oracle
Bouncycastle [ http://www.bouncycastle.org ]
   bcprov-jdk15on-150.jar * extended encryption utils
   bcpkix-jdk15on-150.jar * PKI functionality to access stored keys/certificates.
Jasypt [ http://www.jasypt.org/ ]
   jasypt-1.9.2.jar       * simplifed access to encryption utils
Unicode Project [ http://icu-project.org/ ]
   icu4j-3.4.4.jar        * International Components for Unicode
This Project
   tomcat-extension-0.1.0.jar
```

Acknowledgments:

Thanks to the people at http://www.jasypt.org/ for their wrappers wound the encryption module to make life easier.

Thanks to the people at http://www.bouncycastle.org/ for providing, fast and strong encryption.

And not least to the people at http://tomcat.apache.org/ for providing an excellent application server.





