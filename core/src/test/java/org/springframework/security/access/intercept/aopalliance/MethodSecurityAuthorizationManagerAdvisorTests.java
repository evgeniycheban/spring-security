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
import org.aopalliance.intercept.MethodInvocation;
import org.junit.Test;

import org.springframework.aop.ClassFilter;
import org.springframework.aop.MethodMatcher;
import org.springframework.aop.support.ComposablePointcut;
import org.springframework.security.access.method.AuthorizationMethodAfterAdvice;
import org.springframework.security.access.method.AuthorizationMethodBeforeAdvice;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link MethodSecurityAuthorizationManagerAdvisor}.
 *
 * @author Evgeniy Cheban
 */
public class MethodSecurityAuthorizationManagerAdvisorTests {

	@Test
	public void getPointcutWhenBeforeAfterAdvicesProvidedThenUnionPointcut() {
		Advice mockAdvice = mock(Advice.class);
		AuthorizationMethodBeforeAdvice<MethodInvocation> mockBeforeAdvice = mock(
				AuthorizationMethodBeforeAdvice.class);
		given(mockBeforeAdvice.getClassFilter()).willReturn(ClassFilter.TRUE);
		given(mockBeforeAdvice.getMethodMatcher()).willReturn(MethodMatcher.TRUE);
		AuthorizationMethodAfterAdvice<MethodInvocation> mockAfterAdvice = mock(AuthorizationMethodAfterAdvice.class);
		given(mockAfterAdvice.getClassFilter()).willReturn(ClassFilter.TRUE);
		given(mockAfterAdvice.getMethodMatcher()).willReturn(MethodMatcher.TRUE);
		MethodSecurityAuthorizationManagerAdvisor advisor = new MethodSecurityAuthorizationManagerAdvisor(mockAdvice,
				mockBeforeAdvice, mockAfterAdvice);
		assertThat(advisor.getPointcut()).isInstanceOf(ComposablePointcut.class);
	}

	@Test
	public void getAdviceWhenAdviceProvidedThenAdvice() {
		Advice mockAdvice = mock(Advice.class);
		AuthorizationMethodBeforeAdvice<MethodInvocation> mockBeforeAdvice = mock(
				AuthorizationMethodBeforeAdvice.class);
		given(mockBeforeAdvice.getClassFilter()).willReturn(ClassFilter.TRUE);
		given(mockBeforeAdvice.getMethodMatcher()).willReturn(MethodMatcher.TRUE);
		AuthorizationMethodAfterAdvice<MethodInvocation> mockAfterAdvice = mock(AuthorizationMethodAfterAdvice.class);
		given(mockAfterAdvice.getClassFilter()).willReturn(ClassFilter.TRUE);
		given(mockAfterAdvice.getMethodMatcher()).willReturn(MethodMatcher.TRUE);
		MethodSecurityAuthorizationManagerAdvisor advisor = new MethodSecurityAuthorizationManagerAdvisor(mockAdvice,
				mockBeforeAdvice, mockAfterAdvice);
		assertThat(advisor.getAdvice()).isEqualTo(mockAdvice);
	}

}
