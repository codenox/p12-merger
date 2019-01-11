/**
 * 
 */
package com.codenox.p12merger;

import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.codenox.p12merger.beans.P12Certificate;
import com.codenox.p12merger.beans.P12KeyEntry;

/**
 * @author nox
 *
 */
public class P12Merger {



	public static void main(String[] args) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
		if(args.length == 0) {
			System.out.println("Usage: java -jar p12-merger.jar <p12File> [p12File [p12File...]]  <non-existing-target-p12-file>");
			System.out.println("This will generate a new p12 file, including all p12 provided. ");
			System.exit(1);
		}

		System.out.println("");
		List<File> p12Files = checkFileExistens(args);

		File targetP12 = new File(args[args.length - 1]);

		//		System.out.println("Checking file access for: " + targetP12.getAbsolutePath());
		if(targetP12.exists()) {
			System.err.println(targetP12.getAbsolutePath() + " already exists, will not overwrite it for safety reasons :)");
			System.exit(1);
		}

		if(!targetP12.getAbsoluteFile().getParentFile().isDirectory()) {
			System.err.println(targetP12.getParentFile().getAbsolutePath() + " is not a folder. (which I can write the merged file into)");
			System.exit(1);
		}

		mergeCertificates(p12Files, targetP12);

	}


	/**
	 * @param args
	 */
	private static List<File> checkFileExistens(String[] args) {
		List<File> fileList = new ArrayList<File>();
		for(int i = 0; i < args.length - 1; i++) {
			String p12Path = args[i];
			File p12File = new File(p12Path);
			if(!p12File.exists() || !p12File.canRead()) {
				System.err.println("Cannot find or read: " + p12File.getAbsolutePath());
				System.exit(1);
			}
			fileList.add(p12File);
		}
		return fileList;
	}


	/**
	 * @param args
	 */
	private static void mergeCertificates(List<File> p12List, File targetP12) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
		List<P12Certificate> certList = new ArrayList<P12Certificate>();
		List<P12KeyEntry> keyList = new ArrayList<P12KeyEntry>();
		Console console = System.console();

		for(File p12File : p12List) {
			System.out.println("");
			System.out.println("Opening: " + p12File.getName());
			char[] password = readPasswordAndCheck(p12File, console);
			System.out.println("");
			KeyStore keyStore = getKeyStore(p12File, password);

			for(String alias : Collections.list(keyStore.aliases())) {
				if(keyStore.isCertificateEntry(alias)) {
					Certificate certificate = keyStore.getCertificate(alias);
					certList.add(new P12Certificate(alias, certificate));
					System.out.println("File:" + p12File.getName() + ": Found Certificate '" + alias + "': " + certificate.getType());
				} else if(keyStore.isKeyEntry(alias)) {
					Key key = keyStore.getKey(alias, password);
					Certificate[] certificateChain = keyStore.getCertificateChain(alias);
					keyList.add(new P12KeyEntry(alias, key, certificateChain));
					System.out.println("File:" + p12File.getName() + ": Found Key '" + alias + "' with a Cert-Chain of " + certificateChain.length + " entries");
				}
			}
		}

		System.out.println("## Successfully read all p12 files. ##");
		System.out.println("");

		char[] password = getP12MergedPassword(console);

		writeP12MergedFile(targetP12, certList, keyList, password);

	}


	/**
	 * @return
	 */
	private static char[] getP12MergedPassword(Console console) {
		char[] password = console.readPassword("Please enter password for the merged p12 container: ");
		char[] password2 = console.readPassword("Confirm: ");

		if(!Arrays.equals(password, password2)) {
			System.err.println("Passwords do not match, try again...");
			System.err.println("");
			return getP12MergedPassword(console);
		}

		return password;
	}


	private static KeyStore getKeyStore(File p12File, char[] password) {
		try (InputStream stream = new FileInputStream(p12File)) {
			KeyStore store = KeyStore.getInstance("PKCS12");
			store.load(stream, password);
			return store;
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			System.err.println("Error?");
			e.printStackTrace();
			System.exit(1);
			return null;
		}
	}


	/**
	 * @param certList
	 * @param keyList
	 * @param password
	 */
	private static void writeP12MergedFile(File targetP12, List<P12Certificate> certList, List<P12KeyEntry> keyList, char[] password) {
		System.out.println("Writing: " + targetP12.getAbsolutePath());
		Set<String> usedAlias = new HashSet<>();

		try (OutputStream outstream = new FileOutputStream(targetP12)) {
			KeyStore store = KeyStore.getInstance("PKCS12");
			store.load(null, password);
			for(P12Certificate certificate : certList) {
				String alias = certificate.getAlias();
				if(usedAlias.contains(alias)) {
					alias += "#";
					usedAlias.add(alias);
				} else {
					usedAlias.add(alias);
				}
				store.setCertificateEntry(alias, certificate.getCertificate());
				System.out.println("Adding certificate '" + alias + "': " + certificate.getCertificate().getType());
			}
			for(P12KeyEntry keyEntry : keyList) {
				String alias = keyEntry.getAlias();
				if(usedAlias.contains(alias)) {
					alias += "#";
					usedAlias.add(alias);
				} else {
					usedAlias.add(alias);
				}
				store.setKeyEntry(alias, keyEntry.getKey(), password, keyEntry.getCertChain());
				System.out.println("Adding keyEntry '" + alias + "' with a Cert-Chain of " + keyEntry.getCertChain().length + " entries");
			}

			store.store(outstream, password);

			System.out.println("Done file written: " + targetP12.getAbsolutePath());
		} catch (FileNotFoundException e) {
			System.err.println("File Not Found: " + targetP12.getAbsolutePath());
			System.exit(1);
		} catch (KeyStoreException e) {
			System.err.println("PKCS12 is not support by your JAVA :( " + e.getMessage());
			System.exit(1);
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}


	/**
	 * @param p12File
	 * @param console
	 * @return
	 * @throws FileNotFoundException
	 * @throws KeyStoreException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 */
	private static char[] readPasswordAndCheck(File p12File, Console console) {
		char[] password = console.readPassword("Please enter your password: ");
		try (InputStream stream = new FileInputStream(p12File)) {
			KeyStore store = KeyStore.getInstance("PKCS12");
			store.load(stream, password);
			return password;
		} catch (FileNotFoundException e) {
			System.err.println("File Not Found: " + p12File.getAbsolutePath());
			System.exit(1);
		} catch (KeyStoreException e) {
			System.err.println("PKCS12 is not support by your JAVA :( " + e.getMessage());
			System.exit(1);
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Is this really a p12? " + e.getMessage());
			System.exit(1);
		} catch (CertificateException e) {
			System.err.println("Unable to load p12:  " + e.getMessage());
			System.exit(1);
		} catch (IOException e) {
			System.err.println("Password incorrect, or not a P12:" + e.getMessage());
			System.err.println("");
			return readPasswordAndCheck(p12File, console);
		}
		return null;
	}

}
