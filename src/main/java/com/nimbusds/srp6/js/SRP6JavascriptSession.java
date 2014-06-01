package com.nimbusds.srp6.js;

import java.math.BigInteger;

import com.nimbusds.srp6.SRP6Session;

import static com.nimbusds.srp6.BigIntegerUtils.toHex;

public abstract class SRP6JavascriptSession extends SRP6Session {
	
	/**
	 * Creates a new SRP-6a authentication session.
	 * 
	 * @param timeout
	 *            The SRP-6a authentication session timeout in seconds. If the
	 *            authenticating counterparty (server or client) fails to
	 *            respond within the specified time the session will be closed.
	 *            If zero timeouts are disabled.
	 */
	public SRP6JavascriptSession(final int timeout) {
		super(timeout);
	}

	/**
	 * Creates a new SRP-6a authentication session, session timeouts are
	 * disabled.
	 */
	public SRP6JavascriptSession() {
		this(0);
	}

	/**
	 * Gets the shared session key 'S' or its hash H(S).
	 * <p>
	 * Hashing is done on the hex representation of 'S' for browser
	 * Compatibility.
	 * 
	 * @param doHash
	 *            If {@code true} the hash H(S) of the session key will be
	 *            returned instead of the raw value.
	 * 
	 * @return The shared session key 'S' or its hash H(S). {@code null} will be
	 *         returned if authentication failed or the method is invoked in a
	 *         session state when the session key 'S' has not been computed yet.
	 */
	public BigInteger getSessionKey(final boolean doHash) {
	
		if (S == null)
			return null;
	
		if (doHash) {
			digest.reset();
			return SRP6JavascriptRoutines.hashValues(digest, toHex(S));
		}
		else {
			return S;
		}
	}
	
}
