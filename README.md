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


**Sample: catalina.properties**
```
org.apache.tomcat.util.digester.PROPERTY_SOURCE=com.develop4.security.tomcat.PropertyDecoderService
com.develop4.security.tomcat.PropertyDecoderService.configuration=${catalina.base}/restricted/settings/decoder.properties
```

**Sample: decoder.properties**
```
com.develop4.security.tomcat.PropertyDecoderService.passphrase=${catalina.base}/restricted/keystore/secure.file
com.develop4.security.tomcat.PropertyDecoderService.properties=${catalina.base}/restricted/properties/application.properties
com.develop4.security.tomcat.PropertyDecoderService.decoder.1=com.develop4.security.utils.decoders.NullDecoder
com.develop4.security.utils.decoders.NullDecoder.debug=true
com.develop4.security.tomcat.PropertyDecoderService.decoder.2=com.develop4.security.utils.decoders.Base64Decoder
com.develop4.security.tomcat.PropertyDecoderService.decoder.3=com.develop4.security.utils.decoders.HexDecoder
com.develop4.security.tomcat.PropertyDecoderService.decoder.4=com.develop4.security.utils.decoders.PBEDecoder
```

**Sample: secure.file (Encrypted Master Key)**
```
hex://33306636336330322d626539342d343065392d623034302d646661623033333661643930
```

**Sample: application.properties**
```
my.test.property.one=null://123456789asdf
my.test.property.two=base64://RGV2ZWxvcDRQcm9wZXJ0aWVz
my.test.property.three=hex://446576656c6f7034546563686e6f6c6f67696573
my.test.property.four=pbe://380D5EB7A79BDD4B73B27F7BD22E0F232D4104D8C6C90033F07D680AD7876E62CF905F0D189628CEDF24CADEA388BDCF
tomcat.conf.groupdirectory.user=pbe://B18B73A3C81408DD637BBF4CDC884F1BB1E24845F31EC3237A165BB8568EB0F5
tomcat.conf.groupdirectory.password=pbe://1E5452D5088A87251182917E79056B45216B67277BFFD25DA438D3BE153C29C8
```

**Sample: context.xml**
```
<Context>
    <Environment name="GroupDirectory/LDAPUser" value="${tomcat.conf.groupdirectory.ldap.user}"     override="false" type="java.lang.String"/>
    <Environment name="GroupDirectory/LDAPPass" value="${tomcat.conf.groupdirectory.ldap.password}" override="false" type="java.lang.String"/>
</Context>
```

**Sample: server.xml**
```
<Resource name="jdbc/Reporter"
    connectionPoolName="Reporter"
    url="jdbc:oracle:thin:@smackdown.gov.uk:9801:DONTLOOK1"
    user="${tomcat.conf.server.jdbc.Reporter.user}"
    password="${tomcat.conf.server.jdbc.Reporter.password}"
/>
```

Acknowledgments:

Thanks to the people at http://www.jasypt.org/ for their wrappers wound the encryption module to make life easier.

Thanks to the people at http://www.bouncycastle.org/ for providing, fast and strong encryption.

And not least to the people at http://tomcat.apache.org/ for providing an excellent application server.





