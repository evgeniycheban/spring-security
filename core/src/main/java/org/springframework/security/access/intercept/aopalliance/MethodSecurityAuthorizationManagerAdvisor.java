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

import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;

import org.springframework.aop.Pointcut;
import org.springframework.aop.support.AbstractPointcutAdvisor;
import org.springframework.aop.support.Pointcuts;
import org.springframework.security.access.method.AuthorizationManagerAfterAdvice;
import org.springframework.security.access.method.AuthorizationManagerBeforeAdvice;

/**
 * Advisor driven by the {@link AuthorizationManagerBeforeAdvice} and the
 * {@link AuthorizationManagerAfterAdvice}, used to exclude a {@link MethodInterceptor}
 * from public (non-secure) methods.
 *
 * @author Evgeniy Cheban
 */
public final class MethodSecurityAuthorizationManagerAdvisor extends AbstractPointcutAdvisor {

	private final Pointcut pointcut;

	private final Advice advice;

	/**
	 * Creates an instance.
	 * @param advice the {@link Advice} to use
	 * @param beforeAdvice the {@link AuthorizationManagerBeforeAdvice} to use
	 * @param afterAdvice the {@link AuthorizationManagerAfterAdvice} to use
	 */
	public MethodSecurityAuthorizationManagerAdvisor(Advice advice,
			AuthorizationManagerBeforeAdvice<MethodInvocation> beforeAdvice,
			AuthorizationManagerAfterAdvice<MethodInvocation> afterAdvice) {
		this.advice = advice;
		this.pointcut = Pointcuts.union(beforeAdvice, afterAdvice);
	}

	@Override
	public Pointcut getPointcut() {
		return this.pointcut;
	}

	@Override
	public Advice getAdvice() {
		return this.advice;
	}

}
