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

package org.springframework.security.access.method;

import java.lang.reflect.Method;
import java.util.List;
import java.util.function.Supplier;

import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.aop.MethodMatcher;
import org.springframework.aop.support.AopUtils;
import org.springframework.aop.support.StaticMethodMatcher;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;

/**
 * An {@link AuthorizationManagerBeforeAdvice} which delegates to a specific
 * {@link AuthorizationManagerBeforeAdvice} and returns the first granted
 * {@link AuthorizationDecision} and the denied {@link AuthorizationDecision} only if one
 * of the {@link AuthorizationManagerAfterAdvice}s denied.
 *
 * @author Evgeniy Cheban
 */
public final class DelegatingAuthorizationManagerBeforeAdvice
		implements AuthorizationManagerBeforeAdvice<MethodInvocation> {

	private final Log logger = LogFactory.getLog(getClass());

	private final MethodMatcher methodMatcher = new StaticMethodMatcher() {
		@Override
		public boolean matches(Method method, Class<?> targetClass) {
			for (AuthorizationManagerBeforeAdvice<MethodAuthorizationContext> delegate : DelegatingAuthorizationManagerBeforeAdvice.this.delegates) {
				MethodMatcher methodMatcher = delegate.getMethodMatcher();
				if (methodMatcher.matches(method, targetClass)) {
					return true;
				}
			}
			return false;
		}
	};

	private final List<AuthorizationManagerBeforeAdvice<MethodAuthorizationContext>> delegates;

	/**
	 * Creates an instance.
	 * @param delegates the {@link AuthorizationManagerBeforeAdvice}s to use
	 */
	public DelegatingAuthorizationManagerBeforeAdvice(
			List<AuthorizationManagerBeforeAdvice<MethodAuthorizationContext>> delegates) {
		this.delegates = delegates;
	}

	@Override
	public MethodMatcher getMethodMatcher() {
		return this.methodMatcher;
	}

	/**
	 * Delegates to a specific {@link AuthorizationManagerBeforeAdvice} and returns the
	 * first granted {@link AuthorizationDecision} and the denied
	 * {@link AuthorizationDecision} only if one of the
	 * {@link AuthorizationManagerAfterAdvice}s denied.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param mi the {@link MethodInvocation} to check
	 * @return an {@link AuthorizationDecision} or null if no
	 * {@link AuthorizationManagerBeforeAdvice}s could decide
	 */
	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication, MethodInvocation mi) {
		if (this.logger.isTraceEnabled()) {
			this.logger.trace(LogMessage.format("Pre Authorizing %s", mi));
		}
		Object target = mi.getThis();
		Class<?> targetClass = (target != null) ? AopUtils.getTargetClass(target) : null;
		MethodAuthorizationContext methodAuthorizationCtx = new MethodAuthorizationContext(mi, targetClass);
		AuthorizationDecision deniedDecision = null;
		for (AuthorizationManagerBeforeAdvice<MethodAuthorizationContext> delegate : this.delegates) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.format("Checking authorization on %s using %s", mi, delegate));
			}
			AuthorizationDecision decision = delegate.check(authentication, methodAuthorizationCtx);
			if (decision == null) {
				continue;
			}
			if (decision.isGranted()) {
				return decision;
			}
			if (deniedDecision == null) {
				deniedDecision = decision;
			}
		}
		if (deniedDecision != null) {
			return deniedDecision;
		}
		this.logger.trace("Abstaining since did not find matching AuthorizationManagerBeforeAdvice");
		return null;
	}

}
