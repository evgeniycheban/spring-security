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

import java.util.function.Supplier;

import org.junit.Test;

import org.springframework.aop.MethodMatcher;
import org.springframework.aop.support.annotation.AnnotationMethodMatcher;
import org.springframework.security.access.intercept.method.MockMethodInvocation;
import org.springframework.security.access.method.MethodAuthorizationContext;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link SecuredAuthorizationManager}.
 *
 * @author Evgeniy Cheban
 */
public class SecuredAnnotationAuthorizationMethodBeforeAdviceTests {

	@Test
	public void methodMatcherWhenMethodHasNotSecuredAnnotationThenNotMatches() throws Exception {
		SecuredAuthorizationManager advice = new SecuredAuthorizationManager();
		MethodMatcher methodMatcher = new AnnotationMethodMatcher(Secured.class, true);
		assertThat(methodMatcher.matches(TestClass.class.getMethod("doSomething"), TestClass.class)).isFalse();
	}

	@Test
	public void methodMatcherWhenMethodHasSecuredAnnotationThenMatches() throws Exception {
		SecuredAuthorizationManager advice = new SecuredAuthorizationManager();
		MethodMatcher methodMatcher = new AnnotationMethodMatcher(Secured.class, true);
		assertThat(methodMatcher.matches(TestClass.class.getMethod("securedUserOrAdmin"), TestClass.class)).isTrue();
	}

	@Test
	public void securedUserOrAdminWhenRoleUserThenGrantedDecision() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"securedUserOrAdmin");
		MethodAuthorizationContext methodAuthorizationContext = new MethodAuthorizationContext(methodInvocation,
				TestClass.class);
		SecuredAuthorizationManager advice = new SecuredAuthorizationManager();
		AuthorizationDecision decision = advice.check(authentication, methodAuthorizationContext);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void securedUserOrAdminWhenRoleAdminThenGrantedDecision() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password",
				"ROLE_ADMIN");
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"securedUserOrAdmin");
		MethodAuthorizationContext methodAuthorizationContext = new MethodAuthorizationContext(methodInvocation,
				TestClass.class);
		SecuredAuthorizationManager advice = new SecuredAuthorizationManager();
		AuthorizationDecision decision = advice.check(authentication, methodAuthorizationContext);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void securedUserOrAdminWhenRoleAnonymousThenDeniedDecision() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password",
				"ROLE_ANONYMOUS");
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"securedUserOrAdmin");
		MethodAuthorizationContext methodAuthorizationContext = new MethodAuthorizationContext(methodInvocation,
				TestClass.class);
		SecuredAuthorizationManager advice = new SecuredAuthorizationManager();
		AuthorizationDecision decision = advice.check(authentication, methodAuthorizationContext);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	public static class TestClass {

		@Secured({ "ROLE_USER", "ROLE_ADMIN" })
		public void securedUserOrAdmin() {

		}

		public void doSomething() {

		}

	}

}
