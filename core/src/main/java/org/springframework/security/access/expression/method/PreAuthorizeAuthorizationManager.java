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

package org.springframework.security.access.expression.method;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.aop.support.AopUtils;
import org.springframework.core.MethodClassKey;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.method.AuthorizationMethodBeforeAdvice;
import org.springframework.security.access.method.MethodAuthorizationContext;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * An {@link AuthorizationMethodBeforeAdvice} which can determine if an
 * {@link Authentication} has access to the {@link MethodInvocation} by evaluating
 * expressions from the {@link PreFilter} and the {@link PreAuthorize} annotations.
 *
 * @author Evgeniy Cheban
 */
public final class PreAuthorizeAuthorizationManager implements AuthorizationManager<MethodAuthorizationContext> {

	private static final AuthorizationAttribute NULL_ATTRIBUTE = new AuthorizationAttribute(null);

	private final Map<MethodClassKey, AuthorizationAttribute> cachedAttributes = new ConcurrentHashMap<>();

	private MethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();

	/**
	 * Sets the {@link MethodSecurityExpressionHandler}.
	 * @param expressionHandler the {@link MethodSecurityExpressionHandler} to use
	 */
	public void setExpressionHandler(MethodSecurityExpressionHandler expressionHandler) {
		Assert.notNull(expressionHandler, "expressionHandler cannot be null");
		this.expressionHandler = expressionHandler;
	}

	/**
	 * Determines if an {@link Authentication} has access to the {@link MethodInvocation}
	 * by evaluating expressions from the {@link PreFilter} and the {@link PreAuthorize}
	 * annotations.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param methodAuthorizationContext the {@link MethodAuthorizationContext} to check
	 * @return an {@link AuthorizationDecision} or null if the {@link PreFilter} and the
	 * {@link PreAuthorize} annotations are not present
	 */
	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication,
			MethodAuthorizationContext methodAuthorizationContext) {
		MethodInvocation methodInvocation = methodAuthorizationContext.getMethodInvocation();
		Method method = methodInvocation.getMethod();
		Class<?> targetClass = methodAuthorizationContext.getTargetClass();
		AuthorizationAttribute attribute = resolveAttribute(method, targetClass);
		if (attribute == NULL_ATTRIBUTE) {
			return null;
		}
		EvaluationContext ctx = this.expressionHandler.createEvaluationContext(authentication.get(), methodInvocation);
		boolean granted = attribute.preAuthorize == null
				|| ExpressionUtils.evaluateAsBoolean(attribute.preAuthorize, ctx);
		return new AuthorizationDecision(granted);
	}

	private AuthorizationAttribute resolveAttribute(Method method, Class<?> targetClass) {
		MethodClassKey cacheKey = new MethodClassKey(method, targetClass);
		return this.cachedAttributes.computeIfAbsent(cacheKey, (k) -> doResolveAttribute(method, targetClass));
	}

	private AuthorizationAttribute doResolveAttribute(Method method, Class<?> targetClass) {
		Method specificMethod = AopUtils.getMostSpecificMethod(method, targetClass);
		PreFilter preFilter = findAnnotation(specificMethod, PreFilter.class);
		PreAuthorize preAuthorize = findAnnotation(specificMethod, PreAuthorize.class);
		if (preFilter == null && preAuthorize == null) {
			return NULL_ATTRIBUTE;
		}
		ExpressionParser expressionParser = this.expressionHandler.getExpressionParser();
		Expression preAuthorizeExpression = (preAuthorize != null && StringUtils.hasText(preAuthorize.value()))
				? expressionParser.parseExpression(preAuthorize.value()) : null;
		return new AuthorizationAttribute(preAuthorizeExpression);
	}

	private <A extends Annotation> A findAnnotation(Method method, Class<A> annotationClass) {
		A annotation = AnnotationUtils.findAnnotation(method, annotationClass);
		if (annotation != null) {
			return annotation;
		}
		return AnnotationUtils.findAnnotation(method.getDeclaringClass(), annotationClass);
	}

	private static final class AuthorizationAttribute {

		private final Expression preAuthorize;

		private AuthorizationAttribute(Expression preAuthorize) {
			this.preAuthorize = preAuthorize;
		}

	}

}
