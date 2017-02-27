package uk.co.develop4.security.utils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;

public final class PEMCertificateUtils {

	
	public static PublicKey getPublicKey(String fileName, String passphrase, String providerName) {
		KeyPair keyPair = null;
		try {
			keyPair = getKeyPairFromOpenSslPemFile(fileName, passphrase, providerName);
			return keyPair.getPublic();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}
	
	public static PrivateKey getPrivateKey(String fileName, String passphrase, String providerName) {
		KeyPair keyPair = null;
		try { 
			keyPair = getKeyPairFromOpenSslPemFile(fileName, passphrase, providerName);
			return keyPair.getPrivate();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}

	private static KeyPair getKeyPairFromOpenSslPemFile(String fileName, String passphrase, String providerName) throws IOException {
        Reader fRd = null;
        PEMParser pemParser = null;
        KeyPair keypair = null;
        try {
	        JcaPEMKeyConverter   converter = new JcaPEMKeyConverter().setProvider(providerName);
	        PEMDecryptorProvider pemProv = new JcePEMDecryptorProviderBuilder().setProvider(providerName).build(passphrase.toCharArray());
	        InputDecryptorProvider pkcs8Prov = new JceOpenSSLPKCS8DecryptorProviderBuilder().build(passphrase.toCharArray());
	        //res = this.getClass().getResourceAsStream(fileName);
	        File file = IOCodecUtils.isFile(fileName);
	        FileReader fr = new FileReader(file);			
            fRd = new BufferedReader(fr);
            pemParser = new PEMParser(fRd);
	        Object obj = pemParser.readObject();

	        if (obj instanceof PEMEncryptedKeyPair) {
	        	keypair = converter.getKeyPair(((PEMEncryptedKeyPair)obj).decryptKeyPair(pemProv));
	        } else if (obj instanceof PKCS8EncryptedPrivateKeyInfo) {
	            keypair = new KeyPair(null, converter.getPrivateKey(((PKCS8EncryptedPrivateKeyInfo)obj).decryptPrivateKeyInfo(pkcs8Prov)));
	        } else if (obj instanceof SubjectPublicKeyInfo) {
	        	keypair = new KeyPair((PublicKey)converter.getPublicKey((SubjectPublicKeyInfo)obj),null);
	        } else if (obj instanceof X509CertificateHolder) {
	        	SubjectPublicKeyInfo sub = (SubjectPublicKeyInfo)((X509CertificateHolder)obj).getSubjectPublicKeyInfo();
	        	keypair = new KeyPair((PublicKey)converter.getPublicKey((SubjectPublicKeyInfo)sub),null);
	        } else {
	        	keypair = converter.getKeyPair((PEMKeyPair)obj);
	        }
        } catch (Exception ex) {
        	ex.printStackTrace();
        } finally {
        	pemParser.close();
        }
        return keypair;
	}	
}
