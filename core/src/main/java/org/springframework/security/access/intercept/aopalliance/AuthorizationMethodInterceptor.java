/*
 * Copyright 2002-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.access.intercept.aopalliance;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;

import org.springframework.security.access.method.AuthorizationManagerAfterAdvice;
import org.springframework.security.access.method.AuthorizationManagerBeforeAdvice;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Provides security interception of AOP Alliance based method invocations.
 *
 * @author Evgeniy Cheban
 */
public final class AuthorizationMethodInterceptor implements MethodInterceptor {

	private final AuthorizationManagerBeforeAdvice<MethodInvocation> beforeAdvice;

	private final AuthorizationManagerAfterAdvice<MethodInvocation> afterAdvice;

	/**
	 * Creates an instance.
	 * @param beforeAdvice the {@link AuthorizationManagerBeforeAdvice} to use
	 * @param afterAdvice the {@link AuthorizationManagerAfterAdvice} to use
	 */
	public AuthorizationMethodInterceptor(AuthorizationManagerBeforeAdvice<MethodInvocation> beforeAdvice,
			AuthorizationManagerAfterAdvice<MethodInvocation> afterAdvice) {
		this.beforeAdvice = beforeAdvice;
		this.afterAdvice = afterAdvice;
	}

	/**
	 * This method should be used to enforce security on a {@link MethodInvocation}.
	 * @param invocation the method being invoked which requires a security decision
	 * @return the returned value from the method invocation
	 */
	@Override
	public Object invoke(MethodInvocation invocation) throws Throwable {
		this.beforeAdvice.verify(this::getAuthentication, invocation);
		Object returnedObject = invocation.proceed();
		return this.afterAdvice.check(this::getAuthentication, invocation, returnedObject);
	}

	private Authentication getAuthentication() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null) {
			throw new AuthenticationCredentialsNotFoundException(
					"An Authentication object was not found in the SecurityContext");
		}
		return authentication;
	}

}
