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

package org.springframework.security.access.annotation;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.aop.support.AopUtils;
import org.springframework.core.MethodClassKey;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.access.method.AuthorizationMethodBeforeAdvice;
import org.springframework.security.access.method.MethodAuthorizationContext;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;

/**
 * An {@link AuthorizationMethodBeforeAdvice} which can determine if an
 * {@link Authentication} has access to the {@link MethodInvocation} by evaluating if the
 * {@link Authentication} contains a specified authority from the Spring Security's
 * {@link Secured} annotation.
 *
 * @author Evgeniy Cheban
 */
public final class SecuredAuthorizationManager implements AuthorizationManager<MethodAuthorizationContext> {

	private static final AuthorizationManager<MethodAuthorizationContext> NULL_MANAGER = (a, o) -> null;

	private final Map<MethodClassKey, AuthorizationManager<MethodAuthorizationContext>> cachedManagers = new ConcurrentHashMap<>();

	/**
	 * Determines if an {@link Authentication} has access to the {@link MethodInvocation}
	 * by evaluating if the {@link Authentication} contains a specified authority from the
	 * Spring Security's {@link Secured} annotation.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param methodAuthorizationContext the {@link MethodAuthorizationContext} to check
	 * @return an {@link AuthorizationDecision} or null if the {@link Secured} annotation
	 * is not present
	 */
	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication,
			MethodAuthorizationContext methodAuthorizationContext) {
		MethodInvocation methodInvocation = methodAuthorizationContext.getMethodInvocation();
		Method method = methodInvocation.getMethod();
		Class<?> targetClass = methodAuthorizationContext.getTargetClass();
		AuthorizationManager<MethodAuthorizationContext> delegate = resolveManager(method, targetClass);
		return delegate.check(authentication, methodAuthorizationContext);
	}

	private AuthorizationManager<MethodAuthorizationContext> resolveManager(Method method, Class<?> targetClass) {
		MethodClassKey cacheKey = new MethodClassKey(method, targetClass);
		return this.cachedManagers.computeIfAbsent(cacheKey, (k) -> doResolveManager(method, targetClass));
	}

	private AuthorizationManager<MethodAuthorizationContext> doResolveManager(Method method, Class<?> targetClass) {
		Method specificMethod = AopUtils.getMostSpecificMethod(method, targetClass);
		Secured secured = findSecuredAnnotation(specificMethod);
		return (secured != null) ? AuthorityAuthorizationManager.hasAnyAuthority(secured.value()) : NULL_MANAGER;
	}

	private Secured findSecuredAnnotation(Method method) {
		Secured secured = AnnotationUtils.findAnnotation(method, Secured.class);
		if (secured != null) {
			return secured;
		}
		return AnnotationUtils.findAnnotation(method.getDeclaringClass(), Secured.class);
	}

}
