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
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;

import org.junit.Test;

import org.springframework.aop.MethodMatcher;
import org.springframework.aop.support.StaticMethodMatcher;
import org.springframework.security.access.intercept.method.MockMethodInvocation;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link DelegatingAuthorizationManagerBeforeAdvice}.
 *
 * @author Evgeniy Cheban
 */
public class DelegatingAuthorizationManagerBeforeAdviceTests {

	@Test
	public void methodMatcherWhenNoneMatchesThenNotMatches() throws Exception {
		List<AuthorizationManagerBeforeAdvice<MethodAuthorizationContext>> delegates = new ArrayList<>();
		delegates.add(new AuthorizationManagerBeforeAdvice<MethodAuthorizationContext>() {
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
			public AuthorizationDecision check(Supplier<Authentication> authentication,
					MethodAuthorizationContext object) {
				return new AuthorizationDecision(false);
			}
		});
		delegates.add(new AuthorizationManagerBeforeAdvice<MethodAuthorizationContext>() {
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
			public AuthorizationDecision check(Supplier<Authentication> authentication,
					MethodAuthorizationContext object) {
				return new AuthorizationDecision(false);
			}
		});
		DelegatingAuthorizationManagerBeforeAdvice advice = new DelegatingAuthorizationManagerBeforeAdvice(delegates);
		MethodMatcher methodMatcher = advice.getMethodMatcher();
		assertThat(methodMatcher.matches(TestClass.class.getMethod("doSomething"), TestClass.class)).isFalse();
	}

	@Test
	public void methodMatcherWhenAnyMatchesThenMatches() throws Exception {
		List<AuthorizationManagerBeforeAdvice<MethodAuthorizationContext>> delegates = new ArrayList<>();
		delegates.add(new AuthorizationManagerBeforeAdvice<MethodAuthorizationContext>() {
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
			public AuthorizationDecision check(Supplier<Authentication> authentication,
					MethodAuthorizationContext object) {
				return new AuthorizationDecision(false);
			}
		});
		delegates.add(new AuthorizationManagerBeforeAdvice<MethodAuthorizationContext>() {
			@Override
			public MethodMatcher getMethodMatcher() {
				return MethodMatcher.TRUE;
			}

			@Override
			public AuthorizationDecision check(Supplier<Authentication> authentication,
					MethodAuthorizationContext object) {
				return new AuthorizationDecision(false);
			}
		});
		DelegatingAuthorizationManagerBeforeAdvice advice = new DelegatingAuthorizationManagerBeforeAdvice(delegates);
		MethodMatcher methodMatcher = advice.getMethodMatcher();
		assertThat(methodMatcher.matches(TestClass.class.getMethod("doSomething"), TestClass.class)).isTrue();
	}

	@Test
	public void checkWhenAnyGrantsThenGrantedDecision() throws Exception {
		List<AuthorizationManagerBeforeAdvice<MethodAuthorizationContext>> delegates = new ArrayList<>();
		delegates.add(new AuthorizationManagerBeforeAdvice<MethodAuthorizationContext>() {
			@Override
			public MethodMatcher getMethodMatcher() {
				return MethodMatcher.TRUE;
			}

			@Override
			public AuthorizationDecision check(Supplier<Authentication> authentication,
					MethodAuthorizationContext object) {
				return new AuthorizationDecision(false);
			}
		});
		delegates.add(new AuthorizationManagerBeforeAdvice<MethodAuthorizationContext>() {
			@Override
			public MethodMatcher getMethodMatcher() {
				return MethodMatcher.TRUE;
			}

			@Override
			public AuthorizationDecision check(Supplier<Authentication> authentication,
					MethodAuthorizationContext object) {
				return null;
			}
		});
		delegates.add(new AuthorizationManagerBeforeAdvice<MethodAuthorizationContext>() {
			@Override
			public MethodMatcher getMethodMatcher() {
				return MethodMatcher.TRUE;
			}

			@Override
			public AuthorizationDecision check(Supplier<Authentication> authentication,
					MethodAuthorizationContext object) {
				return new AuthorizationDecision(true);
			}
		});
		DelegatingAuthorizationManagerBeforeAdvice advice = new DelegatingAuthorizationManagerBeforeAdvice(delegates);
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password");
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomething");
		AuthorizationDecision decision = advice.check(authentication, mockMethodInvocation);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void checkWhenAnyDeniesThenFirstDeniedDecision() throws Exception {
		AuthorizationDecision firstDeniedDecision = new AuthorizationDecision(false);
		List<AuthorizationManagerBeforeAdvice<MethodAuthorizationContext>> delegates = new ArrayList<>();
		delegates.add(new AuthorizationManagerBeforeAdvice<MethodAuthorizationContext>() {
			@Override
			public MethodMatcher getMethodMatcher() {
				return MethodMatcher.TRUE;
			}

			@Override
			public AuthorizationDecision check(Supplier<Authentication> authentication,
					MethodAuthorizationContext object) {
				return null;
			}
		});
		delegates.add(new AuthorizationManagerBeforeAdvice<MethodAuthorizationContext>() {
			@Override
			public MethodMatcher getMethodMatcher() {
				return MethodMatcher.TRUE;
			}

			@Override
			public AuthorizationDecision check(Supplier<Authentication> authentication,
					MethodAuthorizationContext object) {
				return firstDeniedDecision;
			}
		});
		delegates.add(new AuthorizationManagerBeforeAdvice<MethodAuthorizationContext>() {
			@Override
			public MethodMatcher getMethodMatcher() {
				return MethodMatcher.TRUE;
			}

			@Override
			public AuthorizationDecision check(Supplier<Authentication> authentication,
					MethodAuthorizationContext object) {
				return new AuthorizationDecision(false);
			}
		});
		DelegatingAuthorizationManagerBeforeAdvice advice = new DelegatingAuthorizationManagerBeforeAdvice(delegates);
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password");
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomething");
		AuthorizationDecision decision = advice.check(authentication, mockMethodInvocation);
		assertThat(decision).isEqualTo(firstDeniedDecision);
	}

	@Test
	public void checkWhenDidNotFindMatchingDelegateThenAbstainDecision() throws Exception {
		List<AuthorizationManagerBeforeAdvice<MethodAuthorizationContext>> delegates = new ArrayList<>();
		delegates.add(new AuthorizationManagerBeforeAdvice<MethodAuthorizationContext>() {
			@Override
			public MethodMatcher getMethodMatcher() {
				return MethodMatcher.TRUE;
			}

			@Override
			public AuthorizationDecision check(Supplier<Authentication> authentication,
					MethodAuthorizationContext object) {
				return null;
			}
		});
		DelegatingAuthorizationManagerBeforeAdvice advice = new DelegatingAuthorizationManagerBeforeAdvice(delegates);
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password");
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomething");
		AuthorizationDecision decision = advice.check(authentication, mockMethodInvocation);
		assertThat(decision).isNull();
	}

	@Test
	public void checkWhenDelegatesEmptyThenAbstainDecision() throws Exception {
		DelegatingAuthorizationManagerBeforeAdvice advice = new DelegatingAuthorizationManagerBeforeAdvice(
				Collections.emptyList());
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password");
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomething");
		AuthorizationDecision decision = advice.check(authentication, mockMethodInvocation);
		assertThat(decision).isNull();
	}

	public static class TestClass {

		public void doSomething() {

		}

	}

}
