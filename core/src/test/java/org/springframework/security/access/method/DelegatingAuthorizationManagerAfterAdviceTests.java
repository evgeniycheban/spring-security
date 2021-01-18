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

package org.springframework.security.access.method;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import org.junit.Test;

import org.springframework.aop.MethodMatcher;
import org.springframework.aop.support.StaticMethodMatcher;
import org.springframework.security.access.intercept.method.MockMethodInvocation;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link DelegatingAuthorizationManagerAfterAdvice}.
 *
 * @author Evgeniy Cheban
 */
public class DelegatingAuthorizationManagerAfterAdviceTests {

	@Test
	public void methodMatcherWhenNoneMatchesThenNotMatches() throws Exception {
		List<AuthorizationManagerAfterAdvice<MethodAuthorizationContext>> delegates = new ArrayList<>();
		delegates.add(new AuthorizationManagerAfterAdvice<MethodAuthorizationContext>() {
			@Override
			public Object check(Supplier<Authentication> authentication, MethodAuthorizationContext object,
					Object returnedObject) {
				return returnedObject;
			}

			@Override
			public MethodMatcher getMethodMatcher() {
				return new StaticMethodMatcher() {
					@Override
					public boolean matches(Method method, Class<?> targetClass) {
						return false;
					}
				};
			}
		});
		delegates.add(new AuthorizationManagerAfterAdvice<MethodAuthorizationContext>() {
			@Override
			public Object check(Supplier<Authentication> authentication, MethodAuthorizationContext object,
					Object returnedObject) {
				return returnedObject;
			}

			@Override
			public MethodMatcher getMethodMatcher() {
				return new StaticMethodMatcher() {
					@Override
					public boolean matches(Method method, Class<?> targetClass) {
						return false;
					}
				};
			}
		});
		DelegatingAuthorizationManagerAfterAdvice advice = new DelegatingAuthorizationManagerAfterAdvice(delegates);
		MethodMatcher methodMatcher = advice.getMethodMatcher();
		assertThat(methodMatcher.matches(TestClass.class.getMethod("doSomething"), TestClass.class)).isFalse();
	}

	@Test
	public void methodMatcherWhenAnyMatchesThenMatches() throws Exception {
		List<AuthorizationManagerAfterAdvice<MethodAuthorizationContext>> delegates = new ArrayList<>();
		delegates.add(new AuthorizationManagerAfterAdvice<MethodAuthorizationContext>() {
			@Override
			public Object check(Supplier<Authentication> authentication, MethodAuthorizationContext object,
					Object returnedObject) {
				return returnedObject;
			}

			@Override
			public MethodMatcher getMethodMatcher() {
				return new StaticMethodMatcher() {
					@Override
					public boolean matches(Method method, Class<?> targetClass) {
						return false;
					}
				};
			}
		});
		delegates.add(new AuthorizationManagerAfterAdvice<MethodAuthorizationContext>() {
			@Override
			public Object check(Supplier<Authentication> authentication, MethodAuthorizationContext object,
					Object returnedObject) {
				return returnedObject;
			}

			@Override
			public MethodMatcher getMethodMatcher() {
				return MethodMatcher.TRUE;
			}
		});
		DelegatingAuthorizationManagerAfterAdvice advice = new DelegatingAuthorizationManagerAfterAdvice(delegates);
		MethodMatcher methodMatcher = advice.getMethodMatcher();
		assertThat(methodMatcher.matches(TestClass.class.getMethod("doSomething"), TestClass.class)).isTrue();
	}

	@Test
	public void checkWhenDelegatingAdviceModifiesReturnedObjectThenModifiedReturnedObject() throws Exception {
		List<AuthorizationManagerAfterAdvice<MethodAuthorizationContext>> delegates = new ArrayList<>();
		delegates.add(new AuthorizationManagerAfterAdvice<MethodAuthorizationContext>() {
			@Override
			public Object check(Supplier<Authentication> authentication, MethodAuthorizationContext object,
					Object returnedObject) {
				return returnedObject + "b";
			}

			@Override
			public MethodMatcher getMethodMatcher() {
				return MethodMatcher.TRUE;
			}
		});
		delegates.add(new AuthorizationManagerAfterAdvice<MethodAuthorizationContext>() {
			@Override
			public Object check(Supplier<Authentication> authentication, MethodAuthorizationContext object,
					Object returnedObject) {
				return returnedObject + "c";
			}

			@Override
			public MethodMatcher getMethodMatcher() {
				return MethodMatcher.TRUE;
			}
		});
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password");
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomething");
		DelegatingAuthorizationManagerAfterAdvice advice = new DelegatingAuthorizationManagerAfterAdvice(delegates);
		Object result = advice.check(authentication, mockMethodInvocation, "a");
		assertThat(result).isEqualTo("abc");
	}

	public static class TestClass {

		public String doSomething() {
			return null;
		}

	}

}
