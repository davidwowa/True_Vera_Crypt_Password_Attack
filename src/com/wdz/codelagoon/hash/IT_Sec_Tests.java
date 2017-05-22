package com.wdz.codelagoon.hash;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Random;

public class IT_Sec_Tests {
	public static void main(String[] args) throws NoSuchAlgorithmException, UnsupportedEncodingException {
		String test1 = "test1";
		String test2 = "test2";

		System.out.println("MD5");
		MessageDigest digest_md5 = MessageDigest.getInstance("MD5");
		BigInteger bigInteger_1 = new BigInteger(1, digest_md5.digest(test1.getBytes("UTF-8")));
		System.out.println(bigInteger_1.toString(16));

		BigInteger bigInteger_2 = new BigInteger(1, digest_md5.digest(test2.getBytes("UTF-8")));
		System.out.println(bigInteger_2.toString(16));

		System.out.println("SHA-1");
		MessageDigest digest_r = MessageDigest.getInstance("SHA-1");
		BigInteger bigInteger_r_1 = new BigInteger(1, digest_r.digest(test1.getBytes("UTF-8")));
		System.out.println(bigInteger_r_1.toString(16));

		BigInteger bigInteger_r_2 = new BigInteger(1, digest_r.digest(test2.getBytes("UTF-8")));
		System.out.println(bigInteger_r_2.toString(16));

		System.out.println("SHA-256");
		MessageDigest digest_s = MessageDigest.getInstance("SHA-256");
		BigInteger bigInteger_s_1 = new BigInteger(1, digest_s.digest(test1.getBytes("UTF-8")));
		System.out.println(bigInteger_s_1.toString(16));

		BigInteger bigInteger_s_2 = new BigInteger(1, digest_s.digest(test2.getBytes("UTF-8")));
		System.out.println(bigInteger_s_2.toString(16));

		System.out.println("SALT");
		String password = "password";
		Random random = new Random();
		byte[] saltAsBytes = new byte[16];
		random.nextBytes(saltAsBytes);
		String saltAsString = Base64.getEncoder().encodeToString(saltAsBytes);
		String saltWithPasswordEncoded = Base64.getEncoder().encodeToString(saltAsString.concat(password).getBytes());
		System.out.println("salt->\t" + saltAsString);
		System.out.println("salt + password->\t" + saltWithPasswordEncoded);

		String passwordDecoded = new String(Base64.getDecoder().decode(saltWithPasswordEncoded.getBytes()));
		System.out.println("->" + passwordDecoded);
	}
}