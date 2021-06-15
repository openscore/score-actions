/*
 * (c) Copyright 2020 Micro Focus
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0 which accompany this distribution.
 *
 * The Apache License is available at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.cloudslang.content.ldap.utils;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class LDAPQuery {
    public static final String AD_ILLEGAL_SAM = "\"\\/[]:;|=,+*?<>";
    public static final String CONNECT_TIMEOUT = "com.sun.jndi.ldap.connect.timeout";
    public static final String OPERATION_TIMEOUT = "com.sun.jndi.ldap.read.timeout";
    public static final int DEFAULT_PORT = 636;
    public static final int DEFAULT_PORT_2 = 389;
    private static final char[] specialCharsArray = new char[]{'#', ',', '+', '<', '>', ';', '=', '/'};
    public String specialChars = "#=<>,+;\"/";
    public String splitChar = ",";
    public String SIMPLE = "simple";
    private boolean bUseSecureAuth = true;

    public DirContext MakeLDAPConnection(String host, String username, String password, String connectionTimeout, String executionTimeout) throws NamingException {
        Address address = new Address(host, Address.PORT_NOT_SET, DEFAULT_PORT_2);
        String resolvedHost = address.getHostAndPortForURI();
        Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://" + resolvedHost);
        env.put(Context.SECURITY_AUTHENTICATION, SIMPLE);
        env.put(Context.SECURITY_PRINCIPAL, username);
        env.put(Context.SECURITY_CREDENTIALS, password);
        env.put(CONNECT_TIMEOUT, connectionTimeout);
        env.put(OPERATION_TIMEOUT, executionTimeout);
        env.put(Context.REFERRAL, "follow");
        DirContext ctx = new InitialDirContext(env);
        return ctx;
    }

    //implemented for possible future use, if we will deal with LDAP referrals; referral can have the value "ignore"(=the default), "throw" or "follow".
    public DirContext MakeLDAPConnectionReferral(String host, String username, String password, String referral) throws NamingException {
        Address address = new Address(host, Address.PORT_NOT_SET, DEFAULT_PORT_2);
        String resolvedHost = address.getHostAndPortForURI();
        Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://" + resolvedHost);
        env.put(Context.SECURITY_AUTHENTICATION, SIMPLE);
        env.put(Context.SECURITY_PRINCIPAL, username);
        env.put(Context.SECURITY_CREDENTIALS, password);
        env.put(Context.REFERRAL, referral);
        DirContext ctx = new InitialDirContext(env);
        return ctx;
    }

    public DirContext MakeLDAPConnection(String host, String dN, String username, String password, String connectionTimeout, String executionTimeout) throws NamingException {
        Address address = new Address(host, Address.PORT_NOT_SET, DEFAULT_PORT_2);
        String resolvedHost = address.getHostAndPortForURI();
        Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://" + resolvedHost + "/" + dN);
        env.put(Context.SECURITY_AUTHENTICATION, SIMPLE);
        env.put(Context.SECURITY_PRINCIPAL, username);
        env.put(Context.SECURITY_CREDENTIALS, password);
        env.put(CONNECT_TIMEOUT, connectionTimeout);
        env.put(OPERATION_TIMEOUT, executionTimeout);
        DirContext ctx = new InitialDirContext(env);
        return ctx;
    }

    public DirContext MakeDummySSLLDAPConnection(String host, String username, String password, String connectionTimeout, String executionTimeout) throws NamingException {
        // init the port with the default value
        Address address = new Address(host, Address.PORT_NOT_SET, DEFAULT_PORT);

        CustomSSLSocket.setTunnelHost("asdasd");
        CustomSSLSocket.setTunnelPort(5467);
        CustomSSLSocket.setIsSecured(true);

        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldaps://" + address.getHostAndPortForURI());
        env.put(Context.SECURITY_AUTHENTICATION, SIMPLE);
        env.put(Context.SECURITY_PRINCIPAL, username);
        env.put(Context.SECURITY_CREDENTIALS, password);
        env.put(CONNECT_TIMEOUT, connectionTimeout);
        env.put(OPERATION_TIMEOUT, executionTimeout);
        env.put(Context.REFERRAL, "ignore");

        /******* VERY IMPORTANT LINE - the parameter is the fully qualified name of your socket factory class *********/
        env.put("java.naming.ldap.factory.socket", "io.cloudslang.content.ldap.utils.CustomSSLSocket");

        return new InitialDirContext(env);
    }

    public DirContext MakeSSLLDAPConnection(String host, String username, String password, String trustAllRoots,
                                            String trustStore, String trustStorePassword, String connectionTimeout, String executionTimeout) throws NamingException {

        // init the port with the default value
        Address address = new Address(host, Address.PORT_NOT_SET, DEFAULT_PORT);

        MySSLSocketFactory.setTrustAllRoots(Boolean.valueOf(trustAllRoots));
        MySSLSocketFactory.setTrustKeystore(trustStore);
        MySSLSocketFactory.setTrustPassword(trustStorePassword);

        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldaps://" + address.getHostAndPortForURI());
        env.put(Context.SECURITY_AUTHENTICATION, SIMPLE);
        env.put(Context.SECURITY_PRINCIPAL, username);
        env.put(Context.SECURITY_CREDENTIALS, password);
        env.put(CONNECT_TIMEOUT, connectionTimeout);
        env.put(OPERATION_TIMEOUT, executionTimeout);
        env.put(Context.REFERRAL, "ignore");

        ///******* VERY IMPORTANT LINE - the parameter is the fully qualified name of your socket factory class *********/
        env.put("java.naming.ldap.factory.socket", "io.cloudslang.content.ldap.utils.MySSLSocketFactory");

        return new InitialDirContext(env);
    }

    //	/<summary>
    ///Escapes the special chracaters that are not escaped by default in the dn path
    ///</summary>
    ///<param name="dn">distinguished name</param>
    ///<param name="oldChars">the chars you want to be escaped</param>
    ///<returns>a new string from dn where oldChars are escaped
    ///<example>oldChars= "=/", dn= cn=!@#<>="/ ==> reuslt: dn= cn=!@#<>\=\/</example>
    ///</returns>
    public String normalizeDN(String dn, boolean remove) {
        StringBuilder rez = new StringBuilder();
        //break DN in its RDN's
        List<String> rdns = getRDNS(dn);
        int i = 0;
        String nRdn;
        for (String rdn : rdns) {
            nRdn = normalizeRDN(rdn, remove);
            if (i++ < rdns.size() - 1) {
                rez.append(nRdn + splitChar);
            } else {
                rez.append(nRdn);
            }
        }
        return rez.toString();
    }


    ///<summary>
    ///Escapes the special chracaters that are not escaped by default in the rdn string
    ///</summary>
    ///<param name="rdn">relative distinguished name</param>
    ///<param name="oldChars">the chars you want to be escaped</param>
    ///<returns>a new string from rdn where oldChars are escaped
    ///<example>ex: oldChars="=/" rdn= cn=!@#$=/ ==> result:rdn= cn=!@#$\=\/</example>
    ///</returns>
    public String normalizeRDN(String rdn, boolean remove) {
        int index = rdn.indexOf("=");
        String rdnType = rdn.substring(0, index + 1);
        String rdnValue = rdn.substring(index + 1);
        rdnValue = normalizeExpression(rdnValue, remove);
        return rdnType + rdnValue;
    }


    ///<summary>
    ///The method breaks the DN into its components.
    ///</summary>
    ///<param name="dn">distinguished name</param>
    ///<returns>a list with rdn components of the dn
    ///</returns>
    private List<String> getRDNS(String DN) {
        List<String> arr = new ArrayList<String>();
        int lastIndex = 0;
        int index = DN.indexOf(splitChar, lastIndex);
        int start = 0;

        //there is only one rdn in the dn
        if (index < 0) {
            arr.add(DN);
        }
        while (index > 0) {
            //We must ignore the cases when "," is preceeded by an odd number of \
            if (isSplitChar(DN, index)) {
                start = (lastIndex == 0) ? lastIndex : lastIndex + 1;
                arr.add(DN.substring(start, index));
                lastIndex = index;
            }

            index = DN.indexOf(splitChar, index + 1);
            if (index < 0)//we must add the last component
            {
                arr.add(DN.substring(lastIndex + 1));
            }
        }
        return arr;
    }


    public String normalizeExpression(String expression, boolean remove) {
        String nDN = expression;
        if (bUseSecureAuth) {
            nDN = normalizeADExpression(expression, remove);
        } else {
            for (int i = 0; i < specialChars.length(); i++) {
                String ch = String.valueOf(specialChars.charAt(i));
                nDN = nDN.replace(ch, "\\" + ch);
            }
        }
        return nDN;
    }

    public String normalizeADExpression(String expression, boolean remove) {
        if (remove)
            return normalizeADExpressionForRemove(expression);

        String nDN = expression;
        nDN = nDN.replace("\\", "\\\\");
        for (int i = 0; i < specialChars.length(); i++) {
            String ch = String.valueOf(specialChars.charAt(i));
            if (!ch.equalsIgnoreCase("/")) {
                nDN = nDN.replace(ch, "\\" + ch);
            }
        }

        return nDN;
    }

    public String normalizeADExpressionForRemove(String expression) {
        String nDN = expression;

        // escaping the \ (backslash) characters from the entire string.
        // The \ character must be replaced with \\\\
        nDN = nDN.replace("\\", "\\\\\\\\");

        // escaping the " (quotes) characters from the entire string.
        // The " character must be replaced with \\"
        nDN = nDN.replace("\"", "\\\\\"");

        for (char c : specialCharsArray) {
            String ch = String.valueOf(c);
            nDN = nDN.replace(ch, "\\" + ch);
        }

        return nDN;
    }

    public String escapeForRemove(String init) {
        // This method replaces in its string input (init):
        //  - the \\ group with \\\\
        //  - the \" group with \\"
        //  - the / group with \/
        Pattern toEscape = Pattern.compile("\\\\[\\\"\\\\]");
        Matcher m = toEscape.matcher(init);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String matched = m.group();
            if (matched.charAt(1) == '\\')
                m.appendReplacement(sb, "\\\\\\\\\\\\\\\\");
            else
                m.appendReplacement(sb, "\\\\\\\\\\\"");
        }
        m.appendTail(sb);
        return sb.toString().replaceAll("/", "\\\\/");
    }

    public String replaceIllegalCharactersForSAM(String sAMAccountName) {
        String sam = sAMAccountName;
        for (char ch : AD_ILLEGAL_SAM.toCharArray()) {
            sam = sam.replace(String.valueOf(ch), "_");
        }
        return sam;
    }

    boolean isSplitChar(String expression, int index) {
        int len = expression.length();
        int poz = 0;
        int crtIndex = index + 1;
        boolean hasEqual = false;

        while (crtIndex < len
                && !splitChar.contains(String.valueOf(expression.charAt(crtIndex)))) {
            if (hasEqual) poz++;
            if (expression.charAt(crtIndex) == '=') {
                hasEqual = true;
            }
            if (!hasEqual) {
                if (specialChars.contains(String.valueOf(expression.charAt(crtIndex)))) {
                    return false;
                }
            }

            crtIndex++;
        }
        if (poz == 0) {
            return false;
        } else {
            return true;
        }

    }
}