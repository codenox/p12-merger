/**
 * 
 */
package com.codenox.p12merger.beans;

import java.security.Key;
import java.security.cert.Certificate;

public class P12KeyEntry {
	private String alias;
	private Key key;
	private Certificate[] certChain;


	/**
	 * @param alias
	 * @param key
	 * @param password
	 * @param certChain
	 */
	public P12KeyEntry(String alias, Key key, Certificate[] certChain) {
		super();
		this.alias = alias;
		this.key = key;
		this.certChain = certChain;
	}


	/**
	 * @return the alias
	 */
	public String getAlias() {
		return alias;
	}


	/**
	 * @return the key
	 */
	public Key getKey() {
		return key;
	}


	/**
	 * @return the certChain
	 */
	public Certificate[] getCertChain() {
		return certChain;
	}

}
