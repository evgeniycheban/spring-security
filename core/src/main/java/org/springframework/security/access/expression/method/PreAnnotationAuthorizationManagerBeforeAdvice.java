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
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.aop.MethodMatcher;
import org.springframework.aop.support.AopUtils;
import org.springframework.aop.support.StaticMethodMatcher;
import org.springframework.core.MethodClassKey;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.method.AuthorizationManagerBeforeAdvice;
import org.springframework.security.access.method.MethodAuthorizationContext;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * An {@link AuthorizationManagerBeforeAdvice} which can determine if an
 * {@link Authentication} has access to the {@link MethodInvocation} by evaluating
 * expressions from the {@link PreFilter} and the {@link PreAuthorize} annotations.
 *
 * @author Evgeniy Cheban
 */
public final class PreAnnotationAuthorizationManagerBeforeAdvice
		implements AuthorizationManagerBeforeAdvice<MethodAuthorizationContext> {

	private static final AuthorizationAttribute NULL_ATTRIBUTE = new AuthorizationAttribute(null, null, null);

	private final MethodMatcher methodMatcher = new StaticMethodMatcher() {
		@Override
		public boolean matches(Method method, Class<?> targetClass) {
			return resolveAttribute(method, targetClass) != NULL_ATTRIBUTE;
		}
	};

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

	@Override
	public MethodMatcher getMethodMatcher() {
		return this.methodMatcher;
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
		if (attribute.preFilter != null) {
			Object filterTarget = findFilterTarget(attribute.filterTarget, ctx, methodInvocation);
			this.expressionHandler.filter(filterTarget, attribute.preFilter, ctx);
		}
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
		String filterTarget = null;
		Expression preFilterExpression = null;
		ExpressionParser expressionParser = this.expressionHandler.getExpressionParser();
		if (preFilter != null) {
			filterTarget = preFilter.filterTarget();
			preFilterExpression = (StringUtils.hasText(preFilter.value()))
					? expressionParser.parseExpression(preFilter.value()) : null;
		}
		Expression preAuthorizeExpression = (preAuthorize != null && StringUtils.hasText(preAuthorize.value()))
				? expressionParser.parseExpression(preAuthorize.value()) : null;
		return new AuthorizationAttribute(filterTarget, preFilterExpression, preAuthorizeExpression);
	}

	private <A extends Annotation> A findAnnotation(Method method, Class<A> annotationClass) {
		A annotation = AnnotationUtils.findAnnotation(method, annotationClass);
		if (annotation != null) {
			return annotation;
		}
		return AnnotationUtils.findAnnotation(method.getDeclaringClass(), annotationClass);
	}

	private Object findFilterTarget(String filterTargetName, EvaluationContext ctx, MethodInvocation methodInvocation) {
		Object filterTarget = null;
		if (StringUtils.hasText(filterTargetName)) {
			filterTarget = ctx.lookupVariable(filterTargetName);
			Assert.notNull(filterTarget, () -> "Filter target was null, or no argument with name '" + filterTargetName
					+ "' found in method");
		}
		else {
			Object[] arguments = methodInvocation.getArguments();
			Assert.state(arguments.length == 1,
					"Unable to determine the method argument for filtering. Specify the filter target.");
			Object arg = arguments[0];
			if (arg instanceof Collection<?>) {
				filterTarget = arg;
			}
			Assert.notNull(filterTarget, () -> "A PreFilter expression was set but the method argument type "
					+ arg.getClass() + " is not filterable");
		}
		return filterTarget;
	}

	private static final class AuthorizationAttribute {

		private final String filterTarget;

		private final Expression preFilter;

		private final Expression preAuthorize;

		private AuthorizationAttribute(String filterTarget, Expression preFilter, Expression preAuthorize) {
			this.filterTarget = filterTarget;
			this.preFilter = preFilter;
			this.preAuthorize = preAuthorize;
		}

	}

}
