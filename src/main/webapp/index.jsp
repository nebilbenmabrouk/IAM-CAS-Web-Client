<%@page contentType="text/html" %>
<%@page pageEncoding="UTF-8" %>
<%@ page import="java.util.Map" %>
<%@ page import="java.util.Iterator" %>
<%@ page import="java.util.List" %>
<%@ page import="org.ow2.proactive.iam.client.authorization.utils.JWTUtils" %>
<%@ page import="org.ow2.proactive.iam.client.authorization.utils.CredentialsUtils" %>
<%@ page import="org.apache.commons.codec.binary.Base64" %>

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
"http://www.w3.org/TR/html4/loose.dtd">

<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <title>ProActive IAM Client 1</title>
</head>
<body>

<h1>ProActive IAM Client 1</h1>
<p>A Java web application that exercises the CAS protocol features via the Java CAS Client.</p>
<hr>


<a href="logout.jsp" title="Click here to log out"> logout </a>
</p>


<%
String token = request.getParameter("ticket");
%>

<p><b>Authentication JWT Token: </b><%= token %>
</br>

<%
        String[] split_string = token.split("\\.");
        String base64EncodedHeader = split_string[0];
        String base64EncodedBody = split_string[1];
        //String base64EncodedSignature = split_string[2];

        String header = JWTUtils.decodeJWTHeader(base64EncodedHeader);
        String body = JWTUtils.decodeJWTBody(base64EncodedBody);
        String encryptedCreds = JWTUtils.getCredFromJWT(body);

        String creds = CredentialsUtils.decryptCredential(CredentialsUtils.loadKeyFromFile("activeeon-private.p8"),encryptedCreds);
%>

<p><b>Decoded JWT header: </b><%= header %>
</br>

<p><b>Decoded JWT body: </b><%= body %>
</br>

<p><b>Encrypted Credential: </b><%= encryptedCreds %>
</br>

<p><b>Decrypted Credential: </b><%= creds %>
</br>

</body>
</html>