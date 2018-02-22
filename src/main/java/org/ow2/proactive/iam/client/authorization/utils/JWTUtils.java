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
package org.ow2.proactive.iam.client.authorization.utils;

import java.io.IOException;
import java.security.PrivateKey;

import org.apache.commons.codec.binary.Base64;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;


public class JWTUtils {

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

            String[] split_string = jwt.split("\\.");
            String base64EncodedHeader = split_string[0];
            String base64EncodedBody = split_string[1];
            //String base64EncodedSignature = split_string[2];

            String header = decodeJWTHeader(base64EncodedHeader);
            String body = decodeJWTBody(base64EncodedBody);

            PrivateKey privateKey = CredentialsUtils.loadKeyFromFile("activeeon-private.p8");
            String encryptedCreds = getCredFromJWT(body);

            System.out.println("JWT Header: " + header);
            System.out.println("JWT Body: " + body);
            System.out.println("Encrypted Credentials :" + encryptedCreds);
            System.out.println("Decrypted Credentials :" +
                               CredentialsUtils.decryptCredential(privateKey, encryptedCreds));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String decodeJWTHeader(String encodedHeader) {

        Base64 base64Url = new Base64(true);
        String header = new String(base64Url.decode(encodedHeader));

        return header;
    }

    public static String decodeJWTBody(String encodedBody) {

        Base64 base64Url = new Base64(true);
        return new String(base64Url.decode(encodedBody));

    }

    public static String getCredFromJWT(String JWTBody) throws IOException {

        ObjectMapper mapper = new ObjectMapper();
        JsonFactory factory = mapper.getFactory();
        JsonNode actualObj = mapper.readTree(JWTBody);
        JsonNode creds = actualObj.get("credential");

        return creds.textValue();
    }

}
