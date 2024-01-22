package it.unitn.APCM.ACME.Guard;

import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.core5.http.ssl.TLS;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;


public class SecureRestTemplate{
	private final static String kstore_pw = System.getenv("KEYSTORE_PASSWORD");
	private final static String k_pw = System.getenv("KEY_PASSWORD");
	private static SSLContext sc = null;
	private RestTemplate secure_rt;

	public SecureRestTemplate() {
		if (sc == null) {
			try {
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
				if (x509km == null) throw new NullPointerException();

				// TrustManagerFactory
				KeyStore ts = KeyStore.getInstance("JKS");
				InputStream tstoreStream = ClassLoader.getSystemClassLoader().getResourceAsStream("GuardC_truststore.jks");
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
				if (x509tm == null) throw new NullPointerException();

				// Instantiate SecureContext
				sc = SSLContext.getInstance("TLSv1.3");
				sc.init(new KeyManager[]{x509km}, new TrustManager[]{x509tm}, new java.security.SecureRandom());
			} catch (IOException | UnrecoverableKeyException | CertificateException | NoSuchAlgorithmException |
					 KeyStoreException | KeyManagementException e) {
				throw new RuntimeException(e);
			}
		}

		PoolingHttpClientConnectionManager connectionManager = PoolingHttpClientConnectionManagerBuilder.create()
				.setSSLSocketFactory(SSLConnectionSocketFactoryBuilder.create()
						.setSslContext(sc)
						.setTlsVersions(TLS.V_1_3)
						.build())
				.build();
		HttpClient httpClient = HttpClientBuilder
				.create()
				.setConnectionManager(connectionManager)
				.build();

		HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory();
		factory.setHttpClient(httpClient);
		secure_rt = new RestTemplate(factory);
	}

	public RestTemplate getSecure_rt() {
		return secure_rt;
	}
}
