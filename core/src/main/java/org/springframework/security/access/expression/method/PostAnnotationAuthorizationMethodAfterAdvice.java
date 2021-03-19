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

import org.springframework.aop.MethodMatcher;
import org.springframework.aop.support.AopUtils;
import org.springframework.aop.support.StaticMethodMatcher;
import org.springframework.core.MethodClassKey;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.method.AuthorizationMethodAfterAdvice;
import org.springframework.security.access.method.MethodAuthorizationContext;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * An {@link AuthorizationMethodAfterAdvice} which can determine if an
 * {@link Authentication} has access to the returned object from the
 * {@link MethodInvocation} by evaluating expressions from the {@link PostFilter} and the
 * {@link PostAuthorize} annotations.
 *
 * @author Evgeniy Cheban
 */
public final class PostAnnotationAuthorizationMethodAfterAdvice
		implements AuthorizationMethodAfterAdvice<MethodAuthorizationContext> {

	private static final AuthorizationAttribute NULL_ATTRIBUTE = new AuthorizationAttribute(null, null);

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
	 * Determines if an {@link Authentication} has access to the returned object from the
	 * {@link MethodInvocation} by evaluating expressions from the {@link PostFilter} and
	 * the {@link PostAuthorize} annotations.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param methodAuthorizationContext the {@link MethodAuthorizationContext} to check
	 * @param returnedObject the returned object from the {@link MethodInvocation}
	 * @return the <code>returnedObject</code> from the method argument (possibly modified
	 * by the {@link PostFilter}'s expression)
	 * @throws AccessDeniedException if access is not granted
	 */
	@Override
	public Object after(Supplier<Authentication> authentication, MethodAuthorizationContext methodAuthorizationContext,
			Object returnedObject) {
		MethodInvocation methodInvocation = methodAuthorizationContext.getMethodInvocation();
		Method method = methodInvocation.getMethod();
		Class<?> targetClass = methodAuthorizationContext.getTargetClass();
		AuthorizationAttribute attribute = resolveAttribute(method, targetClass);
		if (attribute == NULL_ATTRIBUTE) {
			return returnedObject;
		}
		EvaluationContext ctx = this.expressionHandler.createEvaluationContext(authentication.get(), methodInvocation);
		if (attribute.postFilter != null && returnedObject != null) {
			returnedObject = this.expressionHandler.filter(returnedObject, attribute.postFilter, ctx);
		}
		this.expressionHandler.setReturnObject(returnedObject, ctx);
		if (attribute.postAuthorize != null && !ExpressionUtils.evaluateAsBoolean(attribute.postAuthorize, ctx)) {
			throw new AccessDeniedException("Access Denied");
		}
		return returnedObject;
	}

	private AuthorizationAttribute resolveAttribute(Method method, Class<?> targetClass) {
		MethodClassKey cacheKey = new MethodClassKey(method, targetClass);
		return this.cachedAttributes.computeIfAbsent(cacheKey, (k) -> doResolveAttribute(method, targetClass));
	}

	private AuthorizationAttribute doResolveAttribute(Method method, Class<?> targetClass) {
		Method specificMethod = AopUtils.getMostSpecificMethod(method, targetClass);
		PostFilter postFilter = findAnnotation(specificMethod, PostFilter.class);
		PostAuthorize postAuthorize = findAnnotation(specificMethod, PostAuthorize.class);
		if (postFilter == null && postAuthorize == null) {
			return NULL_ATTRIBUTE;
		}
		ExpressionParser expressionParser = this.expressionHandler.getExpressionParser();
		Expression postFilterExpression = (postFilter != null && StringUtils.hasText(postFilter.value()))
				? expressionParser.parseExpression(postFilter.value()) : null;
		Expression postAuthorizeExpression = (postAuthorize != null && StringUtils.hasText(postAuthorize.value()))
				? expressionParser.parseExpression(postAuthorize.value()) : null;
		return new AuthorizationAttribute(postFilterExpression, postAuthorizeExpression);
	}

	private <A extends Annotation> A findAnnotation(Method method, Class<A> annotationClass) {
		A annotation = AnnotationUtils.findAnnotation(method, annotationClass);
		if (annotation != null) {
			return annotation;
		}
		return AnnotationUtils.findAnnotation(method.getDeclaringClass(), annotationClass);
	}

	private static final class AuthorizationAttribute {

		private final Expression postFilter;

		private final Expression postAuthorize;

		private AuthorizationAttribute(Expression postFilter, Expression postAuthorize) {
			this.postFilter = postFilter;
			this.postAuthorize = postAuthorize;
		}

	}

}
