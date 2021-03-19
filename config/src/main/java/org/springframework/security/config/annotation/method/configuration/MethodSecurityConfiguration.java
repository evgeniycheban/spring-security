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

package org.springframework.security.config.annotation.method.configuration;

import java.util.ArrayList;
import java.util.List;

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.aop.MethodMatcher;
import org.springframework.aop.support.annotation.AnnotationMethodMatcher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportAware;
import org.springframework.context.annotation.Role;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.annotation.SecuredAuthorizationManager;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.PostAnnotationAuthorizationMethodAfterAdvice;
import org.springframework.security.access.expression.method.PreAuthorizeAuthorizationManager;
import org.springframework.security.access.expression.method.PreFilterAuthorizationMethodBeforeAdvice;
import org.springframework.security.access.intercept.aopalliance.AuthorizationMethodInterceptor;
import org.springframework.security.access.intercept.aopalliance.MethodSecurityAuthorizationManagerAdvisor;
import org.springframework.security.access.method.AuthorizationManagerMethodBeforeAdvice;
import org.springframework.security.access.method.AuthorizationMethodAfterAdvice;
import org.springframework.security.access.method.AuthorizationMethodBeforeAdvice;
import org.springframework.security.access.method.DelegatingAuthorizationMethodAfterAdvice;
import org.springframework.security.access.method.DelegatingAuthorizationMethodBeforeAdvice;
import org.springframework.security.access.method.MethodAuthorizationContext;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * Base {@link Configuration} for enabling Spring Security Method Security.
 *
 * @author Evgeniy Cheban
 * @see EnableMethodSecurity
 */
@Configuration(proxyBeanMethods = false)
@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
final class MethodSecurityConfiguration implements ImportAware {

	private MethodSecurityExpressionHandler methodSecurityExpressionHandler;

	private AuthorizationMethodBeforeAdvice<MethodInvocation> authorizationMethodBeforeAdvice;

	private AuthorizationMethodAfterAdvice<MethodInvocation> authorizationMethodAfterAdvice;

	private int advisorOrder;

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	MethodSecurityAuthorizationManagerAdvisor methodSecurityAdvisor(AuthorizationMethodInterceptor interceptor) {
		MethodSecurityAuthorizationManagerAdvisor advisor = new MethodSecurityAuthorizationManagerAdvisor(interceptor,
				getAuthorizationManagerBeforeAdvice(), getAuthorizationManagerAfterAdvice());
		advisor.setOrder(this.advisorOrder);
		return advisor;
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	AuthorizationMethodInterceptor authorizationMethodInterceptor() {
		return new AuthorizationMethodInterceptor(getAuthorizationManagerBeforeAdvice(),
				getAuthorizationManagerAfterAdvice());
	}

	private MethodSecurityExpressionHandler getMethodSecurityExpressionHandler() {
		if (this.methodSecurityExpressionHandler == null) {
			this.methodSecurityExpressionHandler = new DefaultMethodSecurityExpressionHandler();
		}
		return this.methodSecurityExpressionHandler;
	}

	@Autowired(required = false)
	void setMethodSecurityExpressionHandler(MethodSecurityExpressionHandler methodSecurityExpressionHandler) {
		this.methodSecurityExpressionHandler = methodSecurityExpressionHandler;
	}

	private AuthorizationMethodBeforeAdvice<MethodInvocation> getAuthorizationManagerBeforeAdvice() {
		if (this.authorizationMethodBeforeAdvice == null) {
			this.authorizationMethodBeforeAdvice = createDefaultAuthorizationManagerBeforeAdvice();
		}
		return this.authorizationMethodBeforeAdvice;
	}

	private AuthorizationMethodBeforeAdvice<MethodInvocation> createDefaultAuthorizationManagerBeforeAdvice() {
		List<AuthorizationMethodBeforeAdvice<MethodAuthorizationContext>> beforeAdvices = new ArrayList<>();
		beforeAdvices.add(getPreFilterAuthorizationManagerBeforeAdvice());
		beforeAdvices.add(getPreAuthorizeAuthorizationManagerBeforeAdvice());
		beforeAdvices.add(getSecuredAuthorizationManagerBeforeAdvice());
		return new DelegatingAuthorizationMethodBeforeAdvice(beforeAdvices);
	}

	private AuthorizationMethodBeforeAdvice<MethodAuthorizationContext> getPreFilterAuthorizationManagerBeforeAdvice() {
		PreFilterAuthorizationMethodBeforeAdvice advice = new PreFilterAuthorizationMethodBeforeAdvice();
		advice.setExpressionHandler(getMethodSecurityExpressionHandler());
		return advice;
	}

	private AuthorizationMethodBeforeAdvice<MethodAuthorizationContext> getPreAuthorizeAuthorizationManagerBeforeAdvice() {
		MethodMatcher methodMatcher = new AnnotationMethodMatcher(PreAuthorize.class, true);
		PreAuthorizeAuthorizationManager authorizationManager = new PreAuthorizeAuthorizationManager();
		authorizationManager.setExpressionHandler(getMethodSecurityExpressionHandler());
		return new AuthorizationManagerMethodBeforeAdvice<>(methodMatcher, authorizationManager);
	}

	private AuthorizationMethodBeforeAdvice<MethodAuthorizationContext> getSecuredAuthorizationManagerBeforeAdvice() {
		MethodMatcher methodMatcher = new AnnotationMethodMatcher(Secured.class, true);
		return new AuthorizationManagerMethodBeforeAdvice<>(methodMatcher, new SecuredAuthorizationManager());
	}

	@Autowired(required = false)
	void setAuthorizationManagerBeforeAdvice(
			AuthorizationMethodBeforeAdvice<MethodInvocation> authorizationMethodBeforeAdvice) {
		this.authorizationMethodBeforeAdvice = authorizationMethodBeforeAdvice;
	}

	private AuthorizationMethodAfterAdvice<MethodInvocation> getAuthorizationManagerAfterAdvice() {
		if (this.authorizationMethodAfterAdvice == null) {
			this.authorizationMethodAfterAdvice = createDefaultAuthorizationManagerAfterAdvice();
		}
		return this.authorizationMethodAfterAdvice;
	}

	private AuthorizationMethodAfterAdvice<MethodInvocation> createDefaultAuthorizationManagerAfterAdvice() {
		List<AuthorizationMethodAfterAdvice<MethodAuthorizationContext>> afterAdvices = new ArrayList<>();
		afterAdvices.add(getPostAnnotationAuthorizationManagerAfterAdvice());
		return new DelegatingAuthorizationMethodAfterAdvice(afterAdvices);
	}

	private PostAnnotationAuthorizationMethodAfterAdvice getPostAnnotationAuthorizationManagerAfterAdvice() {
		PostAnnotationAuthorizationMethodAfterAdvice postAnnotationAfterAdvice = new PostAnnotationAuthorizationMethodAfterAdvice();
		postAnnotationAfterAdvice.setExpressionHandler(getMethodSecurityExpressionHandler());
		return postAnnotationAfterAdvice;
	}

	@Autowired(required = false)
	void setAuthorizationManagerAfterAdvice(
			AuthorizationMethodAfterAdvice<MethodInvocation> authorizationMethodAfterAdvice) {
		this.authorizationMethodAfterAdvice = authorizationMethodAfterAdvice;
	}

	@Override
	public void setImportMetadata(AnnotationMetadata importMetadata) {
		this.advisorOrder = (int) importMetadata.getAnnotationAttributes(EnableMethodSecurity.class.getName())
				.get("order");
	}

}
