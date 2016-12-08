package com.hive.jdbc;

import java.io.IOException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.apache.hive.jdbc.HiveConnection;
import org.apache.hive.jdbc.HiveDriver;

/**
 * PreAuthenticatedHiveDriver.
 *
 */
public class PreAuthenticatedHiveDriver extends HiveDriver{
	static {
		try {
			java.sql.DriverManager.registerDriver(new PreAuthenticatedHiveDriver());
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}

	private static final String SYNCHRONIZED_OBJ = "1";

	/*
	 * As per JDBC 3.0 Spec (section 9.2) "If the Driver implementation
	 * understands the URL, it will return a Connection object; otherwise it
	 * returns null"
	 */
	public Connection connect(final String url, final Properties info) throws SQLException {
		return getConnection(url, info);
	}

	private Connection getConnection(final String url, final Properties info) throws SQLException {
		synchronized (SYNCHRONIZED_OBJ) {
			String[] urlParams = url.split(";");
			String krb5_realm = null;
			String krb5_kdc = null;
			JaasConfiguration jaasConf = new JaasConfiguration();
			Configuration.setConfiguration(jaasConf);

			for (String _urlParam : urlParams) {
				if (_urlParam.contains("principal=")) {
					krb5_realm = _urlParam.replace("krb5_realm=", "");
					krb5_realm = krb5_realm.substring(krb5_realm.indexOf("@") + 1);
				}
				if (_urlParam.contains("krb5_kdc=")) {
					krb5_kdc = _urlParam.replace("krb5_kdc=", "");
				}
			}

			System.setProperty("java.security.krb5.realm", krb5_realm);
			System.setProperty("java.security.krb5.kdc", krb5_kdc);

			String subjectName = "SampleClient" + (new Date().getTime());
			Subject signedOnUserSubject = getSubject(info.getProperty("user"), info.getProperty("password"), krb5_realm,
					krb5_kdc, subjectName);
			Connection conn = null;
			try {
				conn = (Connection) Subject.doAs(signedOnUserSubject, new PrivilegedExceptionAction<Object>() {
					public Object run() {
						Connection con = null;
						try {
							con = acceptsURL(url) ? new HiveConnection(url, info) : null;
						} catch (SQLException e) {
							e.printStackTrace();
						}
						return con;
					}
				});
			} catch (PrivilegedActionException e) {
				new SQLException(e);
			}
			return conn;
		}
	}

	private static class JaasConfiguration extends Configuration {

		@Override
		public AppConfigurationEntry[] getAppConfigurationEntry(String appName) {
			Map<String, String> krbOptions = new HashMap<String, String>();
			krbOptions.put("refreshKrb5Config", "true");
			krbOptions.put("storeKey", "true");
			AppConfigurationEntry testClientEntry = new AppConfigurationEntry(
					"com.sun.security.auth.module.Krb5LoginModule", LoginModuleControlFlag.REQUIRED, krbOptions);
			return new AppConfigurationEntry[] { testClientEntry };
		}
	}

	public class MyCallbackHandler implements CallbackHandler {
		String username = null;
		String krb5_realm = null;
		String krb5_kdc = null;
		String password = null;

		public MyCallbackHandler(String username, String password, String krb5_realm, String krb5_kdc) {
			this.username = username;
			this.krb5_realm = krb5_realm;
			this.krb5_kdc = krb5_kdc;
			this.password = password;
		}

		public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
			for (int i = 0; i < callbacks.length; i++) {
				if (callbacks[i] instanceof NameCallback) {
					NameCallback nc = (NameCallback) callbacks[i];
					nc.setName(username + "@" + krb5_realm);
				} else if (callbacks[i] instanceof PasswordCallback) {
					PasswordCallback nc = (PasswordCallback) callbacks[i];
					nc.setPassword(password.toCharArray());
				} else
					throw new UnsupportedCallbackException(callbacks[i], "Unrecognised callback");
			}
		}
	}

	public Subject getSubject(String username, String password, String krb5_realm, String krb5_kdc, String subjectName)
			throws SQLException {
		Subject signedOnUserSubject = null;

		// create a LoginContext based on the entry in the login.conf file
		LoginContext lc;
		try {
			lc = new LoginContext(subjectName, new MyCallbackHandler(username, password, krb5_realm, krb5_kdc));

			// login (effectively populating the Subject)
			lc.login();
			// get the Subject that represents the signed-on user
			signedOnUserSubject = lc.getSubject();
		} catch (LoginException e1) {
			throw new SQLException(e1);
		}
		return signedOnUserSubject;
	}
}