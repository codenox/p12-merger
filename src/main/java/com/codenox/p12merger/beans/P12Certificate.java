/**
 * 
 */
package com.codenox.p12merger.beans;

import java.security.cert.Certificate;

public class P12Certificate {
	private String alias;
	private Certificate certificate;


	/**
	 * @param alias
	 * @param certChain
	 */
	public P12Certificate(String alias, Certificate certificate) {
		super();
		this.alias = alias;
		this.certificate = certificate;
	}


	/**
	 * @return the alias
	 */
	public String getAlias() {
		return alias;
	}


	/**
	 * @return the certificate
	 */
	public Certificate getCertificate() {
		return certificate;
	}

}
