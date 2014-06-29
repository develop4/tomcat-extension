tomcat-extension
================

Digester Extensions for Tomcat 7

Security extensions to allow the encryption of settings in the Tomcat 7 configuration files.  

This extra functionality should keep every auditor in the world happy, as well as dev/ops. 

This new digester allows the separation of Application Credentials and other sensitive information
from them main tomcat configuration files.   The digester configuration, application credentials and passphrases
can all be stored in separate areas under heightened security control.   The plug-able decryption modules allow
for different decryption methods to be employed based on the name space of the cyphertext.  The Decoders default
behavior should allow them to work without additional configuration. If the Decoder does require additional configuration
then parameters can be passed from the decoder.properties file.


**Sample: catalina.properties**
```
org.apache.tomcat.util.digester.PROPERTY_SOURCE=com.develop4.security.tomcat.PropertyDecoderService
com.develop4.security.tomcat.PropertyDecoderService.configuration=${catalina.base}/conf/decoder.properties
```

**Sample: decoder.properties**
```
com.develop4.security.tomcat.PropertyDecoderService.passphrase=${catalina.base}/conf/secure.file
com.develop4.security.tomcat.PropertyDecoderService.properties=${catalina.base}/conf/application.properties
com.develop4.security.tomcat.PropertyDecoderService.decoder.1=com.develop4.security.utils.decoders.NullDecoder
com.develop4.security.utils.decoders.NullDecoder.debug=true
com.develop4.security.tomcat.PropertyDecoderService.decoder.2=com.develop4.security.utils.decoders.Base64Decoder
com.develop4.security.tomcat.PropertyDecoderService.decoder.3=com.develop4.security.utils.decoders.HexDecoder
com.develop4.security.tomcat.PropertyDecoderService.decoder.4=com.develop4.security.utils.decoders.PBEDecoder
```

**Sample: secure.file (Encrypted Master Key)**
```
446576656c6f7034546563686e6f6c6f67696573
```

**Sample: application.properties**
```
my.test.property.one=null://123456789asdf
my.test.property.two=base64://RGV2ZWxvcDRQcm9wZXJ0aWVz
my.test.property.three=hex://446576656c6f7034546563686e6f6c6f67696573
my.test.property.four=pbe://380D5EB7A79BDD4B73B27F7BD22E0F232D4104D8C6C90033F07D680AD7876E62CF905F0D189628CEDF24CADEA388BDCF
database.oracle.password=MyPasswordOne
database.schedule.password=MyPasswordTwo
```

**Sample: context.xml**
```
<Context>
    <Parameter name="EncryptionTest1" value="${my.test.property.one}" override="false"/>
    <Parameter name="EncryptionTest2" value="${my.test.property.two}" override="false"/>
    <Parameter name="EncryptionTest3" value="${my.test.property.three}" override="false"/>
    <Parameter name="EncryptionTest4" value="${my.test.property.four}" override="false"/>   
    <Parameter name="oraclePassword" value="${database.oracle.password}" override="false"/>
	<Parameter name="schedulerPassowrd" value="${database.schedule.password}" override="false"/>
</Context>
```

Acknowledgments:

Thanks to the people at http://www.jasypt.org/ for their wrappers wound the encryption module to make life easier.

Thanks to the people at http://www.bouncycastle.org/ for providing, fast and strong encryption.

And not least to the people at http://tomcat.apache.org/ for providing an excellent application server.





