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
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link DelegatingAuthorizationMethodBeforeAdvice}.
 *
 * @author Evgeniy Cheban
 */
public class DelegatingAuthorizationMethodBeforeAdviceTests {

	@Test
	public void methodMatcherWhenNoneMatchesThenNotMatches() throws Exception {
		List<AuthorizationMethodBeforeAdvice<MethodAuthorizationContext>> delegates = new ArrayList<>();
		delegates.add(new AuthorizationMethodBeforeAdvice<MethodAuthorizationContext>() {
			@Override
			public MethodMatcher getMethodMatcher() {
				return new StaticMethodMatcher() {
					@Override
					public boolean matches(Method method, Class<?> targetClass) {
						return false;
					}
				};
			}

			@Override
			public void before(Supplier<Authentication> authentication, MethodAuthorizationContext object) {
			}
		});
		delegates.add(new AuthorizationMethodBeforeAdvice<MethodAuthorizationContext>() {
			@Override
			public MethodMatcher getMethodMatcher() {
				return new StaticMethodMatcher() {
					@Override
					public boolean matches(Method method, Class<?> targetClass) {
						return false;
					}
				};
			}

			@Override
			public void before(Supplier<Authentication> authentication, MethodAuthorizationContext object) {
			}
		});
		DelegatingAuthorizationMethodBeforeAdvice advice = new DelegatingAuthorizationMethodBeforeAdvice(delegates);
		MethodMatcher methodMatcher = advice.getMethodMatcher();
		assertThat(methodMatcher.matches(TestClass.class.getMethod("doSomething"), TestClass.class)).isFalse();
	}

	@Test
	public void methodMatcherWhenAnyMatchesThenMatches() throws Exception {
		List<AuthorizationMethodBeforeAdvice<MethodAuthorizationContext>> delegates = new ArrayList<>();
		delegates.add(new AuthorizationMethodBeforeAdvice<MethodAuthorizationContext>() {
			@Override
			public MethodMatcher getMethodMatcher() {
				return new StaticMethodMatcher() {
					@Override
					public boolean matches(Method method, Class<?> targetClass) {
						return false;
					}
				};
			}

			@Override
			public void before(Supplier<Authentication> authentication, MethodAuthorizationContext object) {
			}
		});
		delegates.add(new AuthorizationMethodBeforeAdvice<MethodAuthorizationContext>() {
			@Override
			public MethodMatcher getMethodMatcher() {
				return MethodMatcher.TRUE;
			}

			@Override
			public void before(Supplier<Authentication> authentication, MethodAuthorizationContext object) {
			}
		});
		DelegatingAuthorizationMethodBeforeAdvice advice = new DelegatingAuthorizationMethodBeforeAdvice(delegates);
		MethodMatcher methodMatcher = advice.getMethodMatcher();
		assertThat(methodMatcher.matches(TestClass.class.getMethod("doSomething"), TestClass.class)).isTrue();
	}

	public static class TestClass {

		public void doSomething() {

		}

	}

}
