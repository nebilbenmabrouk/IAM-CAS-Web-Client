/*
 * ProActive Parallel Suite(TM):
 * The Open Source library for parallel and distributed
 * Workflows & Scheduling, Orchestration, Cloud Automation
 * and Big Data Analysis on Enterprise Grids & Clouds.
 *
 * Copyright (c) 2007 - 2017 ActiveEon
 * Contact: contact@activeeon.com
 *
 * This library is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Affero General Public License
 * as published by the Free Software Foundation: version 3 of
 * the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * If needed, contact us to obtain a release under GPL Version 2 or 3
 * or a different license than the AGPL.
 */
package org.ow2.proactive.iam.client.authorization.jwt;

import org.apache.commons.codec.binary.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * Created by nebil on 16/02/18.
 */
public class DecodeToken {

    public static final String jwt = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJzY2hlZHVsZXIiLCJpc0Zyb21OZXdMb2dpbiI6InRydWU" +
            "iLCJhdXRoZW50aWNhdGlvbkRhdGUiOiIyMDE4LTAyLTIwVDE4OjA3OjIyLjUyNSswMTowMFtFdXJvcGVcL1BhcmlzXSIsInN1Y2N" +
            "lc3NmdWxBdXRoZW50aWNhdGlvbkhhbmRsZXJzIjoiTGRhcEF1dGhlbnRpY2F0aW9uSGFuZGxlciIsImlzcyI6Imh0dHBzOlwvXC9" +
            "sb2NhbGhvc3Q6ODQ0M1wvY2FzIiwiY24iOiJzY2hlZHVsZXIiLCJjcmVkZW50aWFsVHlwZSI6IlVzZXJuYW1lUGFzc3dvcmRDcmV" +
            "kZW50aWFsIiwiYXVkIjoiaHR0cHM6XC9cL2xvY2FsaG9zdDo4NDQ0XC9pYW0tY2xpZW50LTEiLCJ1aWQiOiJzY2hlZHVsZXIiLCJ" +
            "jcmVkZW50aWFsIjoiRG1pRjBRSm15XC9BandJZkRKbk5hM2lcL3FyWEZTTmdFWXJyOWxWdlJHTHU3eVVwVVozMGdVVERjOUgyZyt" +
            "sNUpFYm5WOHd1UTRFUnJjTXp0Y2lYcGh3TlZ1RTBGRFpoU3IxdkI3NzJHTXFoNnVHXC9Fc01iN0k3VTBqb3dwcVE3R2t6SnFcL3B" +
            "mTUM5QnZqOXRrR3hmZ0E3MTJMcjJlZGc4TE02d2w1RTdvNjg5QT0iLCJhdXRoZW50aWNhdGlvbk1ldGhvZCI6IkxkYXBBdXRoZW5" +
            "0aWNhdGlvbkhhbmRsZXIiLCJsb25nVGVybUF1dGhlbnRpY2F0aW9uUmVxdWVzdFRva2VuVXNlZCI6ImZhbHNlIiwic24iOiJzY2h" +
            "lZHVsZXIiLCJtZW1iZXJPZiI6ImNuPWFkbWluLG91PWdyb3VwcyxkYz1kYWltbGVyLGRjPWNvbSIsImV4cCI6MTUxOTE3NTI2NSw" +
            "iaWF0IjoxNTE5MTQ2NDY1LCJqdGkiOiJTVC0xMi1ibFNjcTQtWHE4cFJndUtRYVBGSFA3Ynpxek0tbG9jYWxob3N0In0.";

    public static final String encryptedCreds = "HOIxZwS4xasZIyawZ6YdhLFvObWUnDnfcZk0MhhHyw+qRL4CtTPDG4dQ21iRg+eM3" +
            "uzP8nrpxKKc93IQHWRmqzdskEG8jAmQDZXEAUvUo2VwYj1h0Bz/UNgbTkmiv4ss5KzGJETAKUVgzSb3iRUiUTGbgQaALgEmox6eKl" +
            "jDIsQ=";

    public static void main(String[] args) {
        try {

            decodeJWT(jwt);

            decryptCredential(encryptedCreds);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String decryptCredential(String encryptedCreds)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        String cred = null;

        // Read Private Key.
        File filePrivateKey = new File("/home/nebil/activeeon-private.p8");

        FileInputStream fis = new FileInputStream("/home/nebil/activeeon-private.p8");
        byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
        fis.read(encodedPrivateKey);
        fis.close();

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        // decode public key
        /*
         * X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubKeyBytes);
         * RSAPublicKey pubKey = (RSAPublicKey) keyFactory.generatePublic(pubSpec);
         */

        /*
         * KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
         * X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
         * encodedPublicKey);
         * PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
         */

        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        // decode private key
        /*
         * PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
         * RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privSpec);
         */

        Base64 base64 = new Base64();

        Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
        byte[] cred64 = base64.decode(encryptedCreds);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        final byte[] cipherData = cipher.doFinal(cred64);
        cred = new String(cipherData);

        System.out.println(cred);

        return cred;
    }

    public static String decodeJWT(String jwt) {
        String jsonJWT = null;

        String[] split_string = jwt.split("\\.");
        String base64EncodedHeader = split_string[0];
        String base64EncodedBody = split_string[1];
        //String base64EncodedSignature = split_string[2];

        System.out.println("~~~~~~~~~ JWT Header ~~~~~~~");
        Base64 base64Url = new Base64(true);
        String header = new String(base64Url.decode(base64EncodedHeader));
        System.out.println("JWT Header : " + header);

        System.out.println("~~~~~~~~~ JWT Body ~~~~~~~");
        String body = new String(base64Url.decode(base64EncodedBody));
        System.out.println("JWT Body : " + body);

        //This line will throw an exception if it is not a signed JWS (as expected)
        jsonJWT = header + "\n" + body;

        return jsonJWT;
    }
}
