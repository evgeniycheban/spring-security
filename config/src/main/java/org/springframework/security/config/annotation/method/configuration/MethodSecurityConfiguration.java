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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportAware;
import org.springframework.context.annotation.Role;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.access.annotation.SecuredAnnotationAuthorizationManagerBeforeAdvice;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.PostAnnotationAuthorizationManagerAfterAdvice;
import org.springframework.security.access.expression.method.PreAnnotationAuthorizationManagerBeforeAdvice;
import org.springframework.security.access.intercept.aopalliance.AuthorizationMethodInterceptor;
import org.springframework.security.access.intercept.aopalliance.MethodSecurityAuthorizationManagerAdvisor;
import org.springframework.security.access.method.AuthorizationManagerAfterAdvice;
import org.springframework.security.access.method.AuthorizationManagerBeforeAdvice;
import org.springframework.security.access.method.DelegatingAuthorizationManagerAfterAdvice;
import org.springframework.security.access.method.DelegatingAuthorizationManagerBeforeAdvice;
import org.springframework.security.access.method.MethodAuthorizationContext;

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

	private AuthorizationManagerBeforeAdvice<MethodInvocation> authorizationManagerBeforeAdvice;

	private AuthorizationManagerAfterAdvice<MethodInvocation> authorizationManagerAfterAdvice;

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

	private AuthorizationManagerBeforeAdvice<MethodInvocation> getAuthorizationManagerBeforeAdvice() {
		if (this.authorizationManagerBeforeAdvice == null) {
			this.authorizationManagerBeforeAdvice = createDefaultAuthorizationManagerBeforeAdvice();
		}
		return this.authorizationManagerBeforeAdvice;
	}

	private AuthorizationManagerBeforeAdvice<MethodInvocation> createDefaultAuthorizationManagerBeforeAdvice() {
		List<AuthorizationManagerBeforeAdvice<MethodAuthorizationContext>> beforeAdvices = new ArrayList<>();
		beforeAdvices.add(getPreAnnotationAuthorizationManagerBeforeAdvice());
		beforeAdvices.add(new SecuredAnnotationAuthorizationManagerBeforeAdvice());
		return new DelegatingAuthorizationManagerBeforeAdvice(beforeAdvices);
	}

	private PreAnnotationAuthorizationManagerBeforeAdvice getPreAnnotationAuthorizationManagerBeforeAdvice() {
		PreAnnotationAuthorizationManagerBeforeAdvice preAnnotationBeforeAdvice = new PreAnnotationAuthorizationManagerBeforeAdvice();
		preAnnotationBeforeAdvice.setExpressionHandler(getMethodSecurityExpressionHandler());
		return preAnnotationBeforeAdvice;
	}

	@Autowired(required = false)
	void setAuthorizationManagerBeforeAdvice(
			AuthorizationManagerBeforeAdvice<MethodInvocation> authorizationManagerBeforeAdvice) {
		this.authorizationManagerBeforeAdvice = authorizationManagerBeforeAdvice;
	}

	private AuthorizationManagerAfterAdvice<MethodInvocation> getAuthorizationManagerAfterAdvice() {
		if (this.authorizationManagerAfterAdvice == null) {
			this.authorizationManagerAfterAdvice = createDefaultAuthorizationManagerAfterAdvice();
		}
		return this.authorizationManagerAfterAdvice;
	}

	private AuthorizationManagerAfterAdvice<MethodInvocation> createDefaultAuthorizationManagerAfterAdvice() {
		List<AuthorizationManagerAfterAdvice<MethodAuthorizationContext>> afterAdvices = new ArrayList<>();
		afterAdvices.add(getPostAnnotationAuthorizationManagerAfterAdvice());
		return new DelegatingAuthorizationManagerAfterAdvice(afterAdvices);
	}

	private PostAnnotationAuthorizationManagerAfterAdvice getPostAnnotationAuthorizationManagerAfterAdvice() {
		PostAnnotationAuthorizationManagerAfterAdvice postAnnotationAfterAdvice = new PostAnnotationAuthorizationManagerAfterAdvice();
		postAnnotationAfterAdvice.setExpressionHandler(getMethodSecurityExpressionHandler());
		return postAnnotationAfterAdvice;
	}

	@Autowired(required = false)
	void setAuthorizationManagerAfterAdvice(
			AuthorizationManagerAfterAdvice<MethodInvocation> authorizationManagerAfterAdvice) {
		this.authorizationManagerAfterAdvice = authorizationManagerAfterAdvice;
	}

	@Override
	public void setImportMetadata(AnnotationMetadata importMetadata) {
		this.advisorOrder = (int) importMetadata.getAnnotationAttributes(EnableMethodSecurity.class.getName())
				.get("order");
	}

}
