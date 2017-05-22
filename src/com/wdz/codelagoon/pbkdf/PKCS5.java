package com.wdz.codelagoon.pbkdf;

import java.util.Arrays;

import com.wdz.codelagoon.hash.Hash;
import com.wdz.utils.codelagoon.BinUtils;

/*
TruPax  Copyright (C) 2015  CODERSLAGOON

TruPax is free software: you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

TruPax is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with
TruPax. If not, see http://www.gnu.org/licenses/.

*/

public class PKCS5 {

    /**
     * PKCS5/PBKDF2 key derivation implementation.
     */
    public static class PBKDF2 {

        private HMAC hmac;
        private Hash.Function hfunc;

        public PBKDF2() {
        }

        /**
         * Default constructor.
         * @param hfunc The hash function instance to use.
         */
        public PBKDF2(Hash.Function hfunc) {
            this.hfunc = hfunc;
            this.hmac = new HMAC();
        }

        /**
         * Derive a key from a password and some salt.
         * @param passw The password bytes.
         * @param salt The salt value.
         * @param iterations Number of iteration to make brute forcing harder.
         * @param keyLen The size of the key to generate.
         * @return The derived key material.
         */
        public static byte[] deriveKey(Hash.Function hashFunction,
                byte[] passw, byte[] salt,
                int iterations,
                int keyLen) {
            byte[] result = new byte[keyLen];

            final int J = 0;
            final int K = hashFunction.hashSize();
            final int U = hashFunction.hashSize() << 1;
            final int B = K + U;
            final byte[] tmp = new byte[K + U + 4];

            HMAC hmac = new HMAC();
            hmac.initialize(hashFunction, passw, 0, passw.length);

            for (int kpos = 0, blk = 1; kpos < keyLen; kpos += K, blk++) {
                BinUtils.writeInt32BE(blk, tmp, B);

                hmac.reset(null, 0, 0);
                hmac.update(salt, 0, salt.length);
                hmac.update(tmp, B, 4);
                hmac.hash(tmp, U);
                System.arraycopy(tmp, U, tmp, J, K);

                for (int i = 1, j = J, k = K; i < iterations; i++) {
                    hmac.reset(passw, 0, passw.length);
                    hmac.update(tmp, j, K);
                    hmac.hash(tmp, k);

                    for (int u = U, v = k; u < B; u++, v++) {
                        tmp[u] ^= tmp[v];
                    }

                    int swp = k;
                    k = j;
                    j = swp;
                }

                int tocpy = Math.min(keyLen - kpos, K);
                System.arraycopy(tmp, U, result, kpos, tocpy);
            }

            Arrays.fill(tmp, (byte)0);

            return result;
        }

        public void erase() {
            this.hfunc.erase();
            this.hmac.erase();
        }

        public String name() {
            return "PBKDF2";
        }
    }
}
