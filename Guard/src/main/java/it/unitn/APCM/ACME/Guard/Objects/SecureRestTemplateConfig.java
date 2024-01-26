package it.unitn.APCM.ACME.Guard.Objects;

import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;

/**
 * The type Secure rest template config.
 */
@Component
public class SecureRestTemplateConfig {

	/**
	 * The constant sslContext.
	 */
	private static SSLContext sslContext = null;

	/**
	 * Instantiates a new Secure rest template config that works with mTLS for
	 * secure connections.
	 */
	public SecureRestTemplateConfig() {
		if (sslContext == null) {
			try {
				// Get the environment variables
				String kstore_pw = System.getenv("KEYSTORE_PASSWORD");
				String k_pw = System.getenv("KEY_PASSWORD");
				if (kstore_pw == null || k_pw == null) {
					throw new NullPointerException();
				}

				// KeyManagerFactory
				KeyStore ks = KeyStore.getInstance("JKS");
				InputStream kstoreStream = ClassLoader.getSystemClassLoader().getResourceAsStream("Guard_keystore.jks");
				ks.load(kstoreStream, kstore_pw.toCharArray());
				KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
				kmf.init(ks, k_pw.toCharArray());
				X509ExtendedKeyManager x509km = null;
				for (KeyManager keyManager : kmf.getKeyManagers()) {
					if (keyManager instanceof X509ExtendedKeyManager) {
						x509km = (X509ExtendedKeyManager) keyManager;
						break;
					}
				}
				if (x509km == null)
					throw new NullPointerException();

				// TrustManagerFactory
				KeyStore ts = KeyStore.getInstance("JKS");
				InputStream tstoreStream = ClassLoader.getSystemClassLoader()
						.getResourceAsStream("GuardC_truststore.jks");
				ts.load(tstoreStream, null);
				TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
				tmf.init(ts);
				X509ExtendedTrustManager x509tm = null;
				for (TrustManager trustManager : tmf.getTrustManagers()) {
					if (trustManager instanceof X509ExtendedTrustManager) {
						x509tm = (X509ExtendedTrustManager) trustManager;
						break;
					}
				}
				if (x509tm == null)
					throw new NullPointerException();

				// Instantiate SecureContext
				sslContext = SSLContext.getInstance("TLSv1.3");
				sslContext.init(new KeyManager[] { x509km }, new TrustManager[] { x509tm },
						new java.security.SecureRandom());
			} catch (IOException | UnrecoverableKeyException | CertificateException | NoSuchAlgorithmException
					| KeyStoreException | KeyManagementException e) {
				throw new RuntimeException(e);
			}
		}
	}

	/**
	 * Secure rest template rest template.
	 *
	 * @return the rest template
	 */
	@Bean
	public RestTemplate secureRestTemplate() {
		// Create the secure RestTemplate
		SSLConnectionSocketFactory sslSocketFactory = SSLConnectionSocketFactoryBuilder.create()
				.setSslContext(sslContext).build();
		HttpClientConnectionManager cm = PoolingHttpClientConnectionManagerBuilder.create()
				.setSSLSocketFactory(sslSocketFactory).build();
		HttpClient httpClient = HttpClients.custom().setConnectionManager(cm).evictExpiredConnections().build();
		HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory(httpClient);
		return new RestTemplate(factory);
	}
}