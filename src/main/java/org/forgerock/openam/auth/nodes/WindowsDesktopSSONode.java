/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2018 ForgeRock AS.
 */


package org.forgerock.openam.auth.nodes;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.modules.windowsdesktopsso.WindowsDesktopSSOConfig;
import com.sun.identity.authentication.spi.HttpCallback;
import com.sun.identity.authentication.util.DerValue;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdUtils;
import com.sun.identity.shared.encode.Base64;
import com.sun.identity.sm.RequiredValueValidator;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.forgerock.http.util.Json;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.sm.validation.FileExistenceValidator;
import org.ietf.jgss.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.security.auth.Subject;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Windows Desktop SSO Node
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class,
        configClass = WindowsDesktopSSONode.Config.class)
public class WindowsDesktopSSONode extends AbstractDecisionNode {

    private static final String REALM_SEPARATOR = "@";
    private static final String NEGOTIATE = "Negotiate";
    private static final String AUTHORIZATION = "Authorization";
    private final static byte[] spnegoOID = {
            (byte) 0x06, (byte) 0x06, (byte) 0x2b, (byte) 0x06, (byte) 0x01,
            (byte) 0x05, (byte) 0x05, (byte) 0x02};
    private final static byte[] KERBEROS_V5_OID = {
            (byte) 0x06, (byte) 0x09, (byte) 0x2a, (byte) 0x86, (byte) 0x48,
            (byte) 0x86, (byte) 0xf7, (byte) 0x12, (byte) 0x01, (byte) 0x02,
            (byte) 0x02};
    private static final String JSON_PARAMETER_NAME = "jsonContent";
    private static final String FAILURE_ATTRIBUTE = "failure";
    private static final String REASON_ATTRIBUTE = "reason";

    private final Logger logger = LoggerFactory.getLogger("amAuth");
    private final Config config;
    private final Realm realm;

    /**
     * Configuration for the node.
     */
    public interface Config {
        /**
         * The header name for zero-page login that will contain the identity's username.
         */
        @Attribute(order = 100, validators = {RequiredValueValidator.class,})
        String principalName();

        /**
         * The header name for zero-page login that will contain the identity's username.
         */
        @Attribute(order = 200, validators = {FileExistenceValidator.class})
        String keytabFileName();

        /**
         * The header name for zero-page login that will contain the identity's username.
         */
        @Attribute(order = 300, validators = {RequiredValueValidator.class})
        String kerberosRealm();

        /**
         * The header name for zero-page login that will contain the identity's username.
         */
        @Attribute(order = 400, validators = {RequiredValueValidator.class})
        String kerberosServerName();

        /**
         * The header name for zero-page login that will contain the identity's username.
         */
        @Attribute(order = 500)
        Set<String> trustedKerberosRealms();

        /**
         * The header name for zero-page login that will contain the identity's username.
         */
        @Attribute(order = 600)
        default boolean returnPrincipalWithDomainName() {
            return false;
        }

        /**
         * The header name for zero-page login that will contain the identity's username.
         */
        @Attribute(order = 700)
        default boolean lookupUserInRealm() {
            return false;
        }

        /**
         * The header name for zero-page login that will contain the identity's username.
         */
        @Attribute(order = 800)
        default boolean kerberosServiceIsInitiator() {
            return true;
        }
    }

    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     * @param realm  The realm the node is in.
     */
    @Inject
    public WindowsDesktopSSONode(@Assisted Config config, @Assisted Realm realm) {
        this.config = config;
        this.realm = realm;
    }

    @Override
    public Action process(TreeContext context) {

        JsonValue newSharedState = context.sharedState.copy();

        HttpServletRequest request = context.request.servletRequest;
        if (request != null && hasWDSSOFailed(request)) {
            logger.debug("Http Auth Failed");
            return goTo(false).build();
        }

        if (!context.getCallback(HttpCallback.class).isPresent()) {
            return Action.send(new HttpCallback(AUTHORIZATION, "WWW-Authenticate", NEGOTIATE, 401)).build();
        }


        Subject serviceSubject = serviceLogin();

        byte[] spnegoToken = getSPNEGOTokenFromHTTPRequest(Objects.requireNonNull(request));
        if (spnegoToken == null) {
            spnegoToken = getSPNEGOTokenFromCallback(context.getCallbacks(HttpCallback.class));
        }

        if (spnegoToken == null) {
            return logErrorAndReturnFalse(newSharedState, "spnego token is not valid.");
        }

        if (logger.isDebugEnabled()) {
            logger.debug("SPNEGO token: \n{}", DerValue.printByteArray(spnegoToken, 0, spnegoToken.length));
        }
        final byte[] kerberosToken = parseToken(spnegoToken);

        if (kerberosToken == null) {
            return logErrorAndReturnFalse(newSharedState, "Kerberos token is not valid.");
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Kerberos token retrieved from SPNEGO token: \n{}",
                    DerValue.printByteArray(kerberosToken, 0, kerberosToken.length));
        }

        String username;
        try {
            username = authenticateToken(serviceSubject, kerberosToken, config.trustedKerberosRealms());
            if (username != null && !username.isEmpty()) {
                return goTo(true).replaceSharedState(newSharedState).build();
            }
        } catch (PrivilegedActionException pe) {
            Exception e = extractException(pe);
            logger.error("Exception thrown trying to authenticate the user\n" + ExceptionUtils.getStackTrace(e));
            if (e instanceof GSSException) {
                int major = ((GSSException) e).getMajor();
                if (major == GSSException.CREDENTIALS_EXPIRED) {
                    logger.debug("Credential expired. Re-establish credential...");
                    serviceSubject = serviceLogin();
                    try {
                        username = authenticateToken(serviceSubject, kerberosToken, config.trustedKerberosRealms());
                        if (username != null && !username.isEmpty()) {
                            logger.debug("Authentication succeeded with new cred.");
                            return goTo(true).replaceSharedState(newSharedState).build();
                        }
                    } catch (PrivilegedActionException ex) {
                        logger.error("Error while validating kerberos token", ex);
                    }
                }
            } else {
                logger.error(
                        "Authentication failed with PrivilegedActionException wrapped GSSException. Stack Trace", e);
            }
        }
        return goTo(false).replaceSharedState(newSharedState).build();
    }

    private Action logErrorAndReturnFalse(JsonValue newSharedState, String text, Object... objects) {
        logger.error(text, objects);
        return goTo(false).replaceSharedState(newSharedState).build();
    }

    private String authenticateToken(final Subject serviceSubject, final byte[] kerberosToken,
                                     final Set<String> trustedRealms)
            throws PrivilegedActionException {

        if (serviceSubject == null) {
            logger.error("Service subject is null");
            return null;
        }

        return Subject.doAs(serviceSubject, (PrivilegedExceptionAction<String>) () -> {
            GSSContext context = GSSManager.getInstance().createContext((GSSCredential) null);
            logger.debug("Context created.");
            byte[] outToken = context.acceptSecContext(kerberosToken, 0, kerberosToken.length);

            if (outToken != null) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Token returned from acceptSecContext: \n" +
                            DerValue.printByteArray(outToken, 0, outToken.length));
                }
            }

            if (!context.isEstablished()) {
                logger.error("#authenticateToken: Cannot establish context !");
                return null;
            } else {
                logger.debug("Context established !");
                GSSName user = context.getSrcName();
                final String userPrincipalName = user.toString();

                // If the whitelist is empty, do not enforce it. This prevents issues with upgrading, and is the
                // expected default behaviour.
                if (!trustedRealms.isEmpty()) {
                    boolean foundTrustedRealm = false;
                    for (final String trustedRealm : trustedRealms) {
                        if (isTokenTrusted(userPrincipalName, trustedRealm)) {
                            foundTrustedRealm = true;
                            break;
                        }
                    }
                    if (!foundTrustedRealm) {
                        logger.error("Kerberos token for {} is not trusted", userPrincipalName);
                        return null;
                    }
                }
                // Check if the user account from the Kerberos ticket exists in the realm.
                String userValue = getUserName(userPrincipalName);
                if (config.lookupUserInRealm()) {
                    AMIdentity identity = IdUtils.getIdentity(userValue, realm);
                    if (identity == null || !identity.isExists() || !identity.isActive()) {
                        throw new NodeProcessException(
                                "WindowsDesktopSSO.authenticateToken: " + ": Unable to find the user " + userValue +
                                        " in org" + realm.toString());
                    }
                }
                logger.debug("WindowsDesktopSSO.authenticateToken:" + "User authenticated: " + user.toString());
                context.dispose();
                return userValue;
            }
        });
    }

    /**
     * Checks the request for an attribute "http-auth-failed".
     *
     * @param request THe HttpServletRequest.
     * @return If the attribute is present and set to true of if IOException occurs during attribute extraction, true is returned, otherwise false is returned.
     */
    private boolean hasWDSSOFailed(HttpServletRequest request) {
        try {
            JsonValue jsonBody = JsonValue.json(Json.readJson(request.getParameter(JSON_PARAMETER_NAME)));
            return jsonBody.isDefined(FAILURE_ATTRIBUTE) && jsonBody.isDefined(REASON_ATTRIBUTE) &&
                    jsonBody.get(FAILURE_ATTRIBUTE).asBoolean().equals(true) &&
                    jsonBody.get(REASON_ATTRIBUTE).asString().equals("http-auth-failed");
        } catch (IOException e) {
            logger.error("IOException occured while trying to extract JSON Attributes {} and {} from request parameter {}",
                    FAILURE_ATTRIBUTE, REASON_ATTRIBUTE, JSON_PARAMETER_NAME, e);
            return true;
        }
    }

    //TODO should be pulled out from the module code
    private byte[] getSPNEGOTokenFromHTTPRequest(HttpServletRequest req) {
        byte[] spnegoToken = null;
        String header = req.getHeader(AUTHORIZATION);
        if ((header != null) && header.startsWith(NEGOTIATE)) {
            header = header.substring(NEGOTIATE.length()).trim();
            spnegoToken = Base64.decode(header);
        }
        return spnegoToken;
    }

    //TODO should be pulled out from the module code
    private byte[] getSPNEGOTokenFromCallback(List<HttpCallback> callbacks) {
        byte[] spnegoToken = null;
        if (callbacks != null && callbacks.size() != 0) {
            String spnegoTokenStr = callbacks.get(0).getAuthorization();
            spnegoToken = Base64.decode(spnegoTokenStr);
        }

        return spnegoToken;
    }

    private byte[] parseToken(byte[] rawToken) {
        byte[] token = rawToken;
        DerValue tmpToken = new DerValue(rawToken);
        if (logger.isDebugEnabled()) {
            logger.debug("token tag: {}", DerValue.printByte(tmpToken.getTag()));
        }
        if (tmpToken.getTag() != (byte) 0x60) {
            return null;
        }

        ByteArrayInputStream tmpInput = new ByteArrayInputStream(tmpToken.getData());

        // check for SPNEGO OID
        byte[] oidArray = new byte[spnegoOID.length];
        tmpInput.read(oidArray, 0, oidArray.length);
        if (Arrays.equals(oidArray, spnegoOID)) {
            logger.debug("SPNEGO OID found in the Auth Token");
            tmpToken = new DerValue(tmpInput);

            // 0xa0 indicates an init token(NegTokenInit); 0xa1 indicates an
            // response arg token(NegTokenTarg). no arg token is needed for us.

            if (tmpToken.getTag() == (byte) 0xa0) {
                logger.debug("DerValue: found init token");
                tmpToken = new DerValue(tmpToken.getData());
                if (tmpToken.getTag() == (byte) 0x30) {
                    logger.debug("DerValue: 0x30 constructed token found");
                    tmpInput = new ByteArrayInputStream(tmpToken.getData());
                    tmpToken = new DerValue(tmpInput);

                    // In an init token, it can contain 4 optional arguments:
                    // a0: mechTypes
                    // a1: contextFlags
                    // a2: octect string(with leading char 0x04) for the token
                    // a3: message integrity value

                    while (tmpToken.getTag() != (byte) -1 &&
                            tmpToken.getTag() != (byte) 0xa2) {
                        // look for next mech token DER
                        tmpToken = new DerValue(tmpInput);
                    }
                    if (tmpToken.getTag() != (byte) -1) {
                        // retrieve octet string
                        tmpToken = new DerValue(tmpToken.getData());
                        token = tmpToken.getData();
                    }
                }
            }
        } else {
            logger.debug("SPNEGO OID not found in the Auth Token");
            byte[] krb5Oid = new byte[KERBEROS_V5_OID.length];
            int i = 0;
            for (; i < oidArray.length; i++) {
                krb5Oid[i] = oidArray[i];
            }
            tmpInput.read(krb5Oid, i, krb5Oid.length - i);
            if (!Arrays.equals(krb5Oid, KERBEROS_V5_OID)) {
                logger.debug("Kerberos V5 OID not found in the Auth Token");
                token = null;
            } else {
                logger.debug("Kerberos V5 OID found in the Auth Token");
            }
        }
        return token;
    }

    private String getUserName(String user) {
        String userName = user;
        if (!config.returnPrincipalWithDomainName()) {
            int index = user.indexOf(REALM_SEPARATOR);
            if (index != -1) {
                userName = user.substring(0, index);
            }
        }
        return userName;
    }

    private Subject serviceLogin() {
        logger.debug("New Service Login ...");
        System.setProperty("java.security.krb5.realm", config.kerberosRealm());
        System.setProperty("java.security.krb5.kdc", config.kerberosServerName());
        WindowsDesktopSSOConfig wtc = new WindowsDesktopSSOConfig(Configuration.getConfiguration());
        wtc.setPrincipalName(config.principalName());
        wtc.setKeyTab(config.keytabFileName());
        wtc.setIsInitiator(config.kerberosServiceIsInitiator());

        LoginContext lc;
        // perform service authentication using JDK Kerberos module
        try {
            lc = new LoginContext(WindowsDesktopSSOConfig.defaultAppName, null, null, wtc);
            lc.login();
        } catch (LoginException e) {
            logger.error("Error while performing service login", e);
            return null;
        }
        Subject serviceSubject = lc.getSubject();
        logger.debug("Service login succeeded.");
        return serviceSubject;
    }


    /**
     * Iterate until we extract the real exception
     * from PrivilegedActionException(s).
     */
    private Exception extractException(Exception e) {
        while (e instanceof PrivilegedActionException) {
            e = ((PrivilegedActionException) e).getException();
        }
        return e;
    }

    private boolean isTokenTrusted(final String UPN, final String realm) {
        boolean trusted = false;
        if (UPN != null) {
            final int param_index = UPN.indexOf(REALM_SEPARATOR);
            if (param_index != -1) {
                final String realmPart = UPN.substring(param_index + 1);
                if (realmPart.equalsIgnoreCase(realm)) {
                    trusted = true;
                }
            }
        }
        return trusted;
    }

}
