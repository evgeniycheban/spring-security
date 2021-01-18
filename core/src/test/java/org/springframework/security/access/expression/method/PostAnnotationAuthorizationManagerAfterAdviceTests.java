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

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import org.junit.Test;

import org.springframework.aop.MethodMatcher;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.intercept.method.MockMethodInvocation;
import org.springframework.security.access.method.MethodAuthorizationContext;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link PostAnnotationAuthorizationManagerAfterAdvice}.
 *
 * @author Evgeniy Cheban
 */
public class PostAnnotationAuthorizationManagerAfterAdviceTests {

	@Test
	public void setExpressionHandlerWhenNotNullThenSetsExpressionHandler() {
		MethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
		PostAnnotationAuthorizationManagerAfterAdvice advice = new PostAnnotationAuthorizationManagerAfterAdvice();
		advice.setExpressionHandler(expressionHandler);
		assertThat(advice).extracting("expressionHandler").isEqualTo(expressionHandler);
	}

	@Test
	public void setExpressionHandlerWhenNullThenException() {
		PostAnnotationAuthorizationManagerAfterAdvice advice = new PostAnnotationAuthorizationManagerAfterAdvice();
		assertThatIllegalArgumentException().isThrownBy(() -> advice.setExpressionHandler(null))
				.withMessage("expressionHandler cannot be null");
	}

	@Test
	public void methodMatcherWhenMethodHasNotPostAnnotationsThenNotMatches() throws Exception {
		PostAnnotationAuthorizationManagerAfterAdvice advice = new PostAnnotationAuthorizationManagerAfterAdvice();
		MethodMatcher methodMatcher = advice.getMethodMatcher();
		assertThat(methodMatcher.matches(TestClass.class.getMethod("doSomething"), TestClass.class)).isFalse();
	}

	@Test
	public void methodMatcherWhenMethodHasPostFilterAnnotationThenMatches() throws Exception {
		PostAnnotationAuthorizationManagerAfterAdvice advice = new PostAnnotationAuthorizationManagerAfterAdvice();
		MethodMatcher methodMatcher = advice.getMethodMatcher();
		assertThat(methodMatcher.matches(TestClass.class.getMethod("doSomethingList", List.class), TestClass.class))
				.isTrue();
	}

	@Test
	public void methodMatcherWhenMethodHasPostAuthorizeAnnotationThenMatches() throws Exception {
		PostAnnotationAuthorizationManagerAfterAdvice advice = new PostAnnotationAuthorizationManagerAfterAdvice();
		MethodMatcher methodMatcher = advice.getMethodMatcher();
		assertThat(methodMatcher.matches(TestClass.class.getMethod("doSomethingString", String.class), TestClass.class))
				.isTrue();
	}

	@Test
	public void postFilterWhenReturningListThenFiltersList() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");
		List<String> list = new ArrayList<>();
		list.add("john");
		list.add("bob");
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingList", new Class[] { List.class }, new Object[] { list });
		MethodAuthorizationContext methodAuthorizationContext = new MethodAuthorizationContext(mockMethodInvocation,
				TestClass.class);
		PostAnnotationAuthorizationManagerAfterAdvice advice = new PostAnnotationAuthorizationManagerAfterAdvice();
		List<String> result = (List<String>) advice.check(authentication, methodAuthorizationContext, list);
		assertThat(result).hasSize(1);
		assertThat(list.get(0)).isEqualTo("john");
	}

	@Test
	public void postAuthorizeWhenArgIsGrantThenReturnedObject() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingString", new Class[] { String.class }, new Object[] { "grant" });
		MethodAuthorizationContext methodAuthorizationContext = new MethodAuthorizationContext(mockMethodInvocation,
				TestClass.class);
		PostAnnotationAuthorizationManagerAfterAdvice advice = new PostAnnotationAuthorizationManagerAfterAdvice();
		Object grant = advice.check(authentication, methodAuthorizationContext, "grant");
		assertThat(grant).isEqualTo("grant");
	}

	@Test
	public void postAuthorizeWhenArgIsNotGrantThenAccessDeniedException() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingString", new Class[] { String.class }, new Object[] { "deny" });
		MethodAuthorizationContext methodAuthorizationContext = new MethodAuthorizationContext(mockMethodInvocation,
				TestClass.class);
		PostAnnotationAuthorizationManagerAfterAdvice advice = new PostAnnotationAuthorizationManagerAfterAdvice();
		assertThatExceptionOfType(AccessDeniedException.class)
				.isThrownBy(() -> advice.check(authentication, methodAuthorizationContext, "deny"))
				.withMessage("Access Denied");
	}

	@Test
	public void postFilterPostAuthorizeWhenListContainsGrantThenFiltersList() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");
		List<String> list = new ArrayList<>();
		list.add("grant");
		list.add("deny");
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingPostFilterPostAuthorizeList", new Class[] { List.class }, new Object[] { list });
		MethodAuthorizationContext methodAuthorizationContext = new MethodAuthorizationContext(mockMethodInvocation,
				TestClass.class);
		PostAnnotationAuthorizationManagerAfterAdvice advice = new PostAnnotationAuthorizationManagerAfterAdvice();
		List<String> result = (List<String>) advice.check(authentication, methodAuthorizationContext, list);
		assertThat(result).hasSize(1);
		assertThat(result.get(0)).isEqualTo("grant");
	}

	@Test
	public void postFilterPostAuthorizeWhenListNotContainsGrantThenAccessDeniedException() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");
		List<String> list = new ArrayList<>();
		list.add("deny");
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingPostFilterPostAuthorizeList", new Class[] { List.class }, new Object[] { list });
		MethodAuthorizationContext methodAuthorizationContext = new MethodAuthorizationContext(mockMethodInvocation,
				TestClass.class);
		PostAnnotationAuthorizationManagerAfterAdvice advice = new PostAnnotationAuthorizationManagerAfterAdvice();
		assertThatExceptionOfType(AccessDeniedException.class)
				.isThrownBy(() -> advice.check(authentication, methodAuthorizationContext, list))
				.withMessage("Access Denied");
		assertThat(list).isEmpty();
	}

	public static class TestClass {

		@PostFilter("filterObject == 'john'")
		public List<String> doSomethingList(List<String> list) {
			return list;
		}

		@PostAuthorize("#s == 'grant'")
		public String doSomethingString(String s) {
			return s;
		}

		@PostFilter("filterObject == 'grant'")
		@PostAuthorize("#list?.contains('grant')")
		public List<String> doSomethingPostFilterPostAuthorizeList(List<String> list) {
			return list;
		}

		public void doSomething() {

		}

	}

}
