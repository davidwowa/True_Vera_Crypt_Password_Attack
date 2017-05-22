package com.wdz;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.LineNumberReader;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.log4j.Logger;

import com.wdz.codelagoon.crypto.AES256;
import com.wdz.codelagoon.crypto.BlockCipher;
import com.wdz.codelagoon.crypto.TCLibException;
import com.wdz.codelagoon.crypto.XTS;
import com.wdz.codelagoon.hash.Hash;
import com.wdz.codelagoon.hash.SHA512;
import com.wdz.codelagoon.pbkdf.PKCS5.PBKDF2;

public class Main {

	static Logger logger = Logger.getLogger(Main.class);

	public static void main(String[] args) {

		// logger.info("use RIPEMD160");
		// start(new RIPEMD160());
		logger.info("use SHA512");
		start(new SHA512());

	}

	private static void start(Hash.Function hashFunction) {

		BlockCipher bcipher1 = new AES256();
		BlockCipher bcipher2 = new AES256();

		byte[] header = new byte[512];
		byte[] salt = new byte[64];

		String container = "resources/vera_cr";
		String passwords = "resources/passwords.txt";

		header = getFirst512BytesFromContainer(container);
		salt = getSalt(header);
		String[] passwordsArray = getPasswordsList(passwords);

		for (int i = 0; i < passwordsArray.length; i++) {
			String password = passwordsArray[i];
			if (logger.isDebugEnabled()) {
				logger.debug(password);
			}
			if (password != null) {
				// for TrueCrypt example ->
				// hashFunction.recommededHMACIterations(false)
				// 2000 for RIPEMD160
				// for VeraCrypt example ->
				// hashFunction.recommededHMACIterations(true)
				// 500000 for SHA512
				byte[] key = PBKDF2.deriveKey(hashFunction, password.getBytes(), salt,
						hashFunction.recommededHMACIterations(true), bcipher1.keySize() + bcipher2.keySize());

				bcipher1.initialize(BlockCipher.Mode.DECRYPT, key, 0);
				bcipher2.initialize(BlockCipher.Mode.ENCRYPT, key, bcipher2.keySize());
				try {
					XTS xts = new XTS(bcipher1, bcipher2);
					xts.process(header, 64, 512 - 64, 0L, 0);

					if (logger.isDebugEnabled()) {
						String currentHeader = new String(header);
						logger.debug("current header->" + currentHeader);
					}

					byte[] isTrue = getWord(header, 64, 67);
					String word = new String(isTrue);
					if (logger.isDebugEnabled()) {
						logger.debug("word->" + word);
					}
					if (word.contains("VERA")) {// for VeraCrypt Container
						// if (word.contains("TRUE")) {// for TrueCrypt
						// Container
						logger.info(word + " " + password + " " + ArrayUtils.toString(isTrue));
						logger.info("header->" + new String(header));
						logger.info("salt->" + new String(salt));

						// TODO decrypt partition
					}
				} catch (TCLibException e) {
					logger.error("error on decryption", e);
					e.printStackTrace();
				}
			}
		}
	}

	static byte[] longToBytes(long x) {
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(x);
		return buffer.array();
	}

	static String[] getPasswordsList(String path) {
		int numberOfPasswords = 0;
		// TODO Bug No 1
		// String charset = "ISO-8859-1";
		String charset = "UTF-8";

		try {
			LineNumberReader lineNumberReader = new LineNumberReader(
					new InputStreamReader(new FileInputStream(path), Charset.forName(charset)));
			lineNumberReader.skip(Long.MAX_VALUE);
			numberOfPasswords = lineNumberReader.getLineNumber();
			logger.info("passwords ammount " + numberOfPasswords);
			lineNumberReader.close();
		} catch (Throwable e) {
			logger.error("error on reading line number on password file", e);
		}

		try (BufferedReader br = new BufferedReader(
				new InputStreamReader(new FileInputStream(path), Charset.forName(charset)))) {
			String[] passwords = new String[numberOfPasswords + 1];

			String currentPassword;
			int count = 0;
			while ((currentPassword = br.readLine()) != null) {
				passwords[count] = currentPassword;
				count++;
			}
			return passwords;
		} catch (Throwable e) {
			logger.error("error on read password file ", e);
		}
		return null;
	}

	static byte[] getWord(byte[] header, int start, int end) {
		int count = 0;
		byte[] result = new byte[(end - start) + 1];
		for (int i = start; i <= end; i++) {
			result[count] = header[i];
			count++;
		}
		return result;
	}

	static byte[] getSalt(byte[] header) {
		byte[] salt = new byte[64];
		for (int i = 0; i < salt.length; i++) {
			salt[i] = header[i];
		}
		return salt;
	}

	static byte[] getFirst512BytesFromContainer(String path) {
		Path patha = Paths.get(path);
		try {
			byte[] allData = Files.readAllBytes(patha);
			byte[] result = new byte[512];
			for (int i = 0; i < result.length; i++) {
				result[i] = allData[i];
			}
			return result;
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
}