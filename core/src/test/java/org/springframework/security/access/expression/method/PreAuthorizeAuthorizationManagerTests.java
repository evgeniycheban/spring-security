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
import org.springframework.aop.support.annotation.AnnotationMethodMatcher;
import org.springframework.security.access.intercept.method.MockMethodInvocation;
import org.springframework.security.access.method.MethodAuthorizationContext;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

/**
 * Tests for {@link PreAuthorizeAuthorizationManager}.
 *
 * @author Evgeniy Cheban
 */
public class PreAuthorizeAuthorizationManagerTests {

	@Test
	public void setExpressionHandlerWhenNotNullThenSetsExpressionHandler() {
		MethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
		PreAuthorizeAuthorizationManager advice = new PreAuthorizeAuthorizationManager();
		advice.setExpressionHandler(expressionHandler);
		assertThat(advice).extracting("expressionHandler").isEqualTo(expressionHandler);
	}

	@Test
	public void setExpressionHandlerWhenNullThenException() {
		PreAuthorizeAuthorizationManager advice = new PreAuthorizeAuthorizationManager();
		assertThatIllegalArgumentException().isThrownBy(() -> advice.setExpressionHandler(null))
				.withMessage("expressionHandler cannot be null");
	}

	@Test
	public void methodMatcherWhenMethodHasNotPreAnnotationsThenNotMatches() throws Exception {
		PreAuthorizeAuthorizationManager advice = new PreAuthorizeAuthorizationManager();
		MethodMatcher methodMatcher = new AnnotationMethodMatcher(PreAuthorize.class, true);
		assertThat(methodMatcher.matches(TestClass.class.getMethod("doSomething"), TestClass.class)).isFalse();
	}

	@Test
	public void methodMatcherWhenMethodHasPreFilterAnnotationThenMatches() throws Exception {
		PreAuthorizeAuthorizationManager advice = new PreAuthorizeAuthorizationManager();
		MethodMatcher methodMatcher = new AnnotationMethodMatcher(PreFilter.class, true);
		assertThat(
				methodMatcher.matches(TestClass.class.getMethod("doSomethingArray", String[].class), TestClass.class))
						.isTrue();
	}

	@Test
	public void methodMatcherWhenMethodHasPreAuthorizeAnnotationThenMatches() throws Exception {
		PreAuthorizeAuthorizationManager advice = new PreAuthorizeAuthorizationManager();
		MethodMatcher methodMatcher = new AnnotationMethodMatcher(PreAuthorize.class, true);
		assertThat(methodMatcher.matches(TestClass.class.getMethod("doSomethingString", String.class), TestClass.class))
				.isTrue();
	}

	@Test
	public void findFilterTargetWhenNameProvidedAndNotMatchThenException() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingListFilterTargetNotMatch", new Class[] { List.class }, new Object[] { new ArrayList<>() });
		MethodAuthorizationContext methodAuthorizationContext = new MethodAuthorizationContext(mockMethodInvocation,
				TestClass.class);
		PreFilterAuthorizationMethodBeforeAdvice filter = new PreFilterAuthorizationMethodBeforeAdvice();
		assertThatIllegalArgumentException().isThrownBy(() -> filter.before(authentication, methodAuthorizationContext))
				.withMessage("Filter target was null, or no argument with name 'filterTargetNotMatch' found in method");
	}

	@Test
	public void findFilterTargetWhenNameProvidedAndMatchAndNullThenException() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingListFilterTargetMatch", new Class[] { List.class }, new Object[] { null });
		MethodAuthorizationContext methodAuthorizationContext = new MethodAuthorizationContext(mockMethodInvocation,
				TestClass.class);
		PreFilterAuthorizationMethodBeforeAdvice filter = new PreFilterAuthorizationMethodBeforeAdvice();
		assertThatIllegalArgumentException().isThrownBy(() -> filter.before(authentication, methodAuthorizationContext))
				.withMessage("Filter target was null, or no argument with name 'list' found in method");
	}
	@Test
	public void findFilterTargetWhenNameProvidedAndMatchAndNotNullThenFiltersListReturningGrantedDecision()
			throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");
		List<String> list = new ArrayList<>();
		list.add("john");
		list.add("bob");
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingListFilterTargetMatch", new Class[] { List.class }, new Object[] { list });
		MethodAuthorizationContext methodAuthorizationContext = new MethodAuthorizationContext(mockMethodInvocation,
				TestClass.class);
		PreFilterAuthorizationMethodBeforeAdvice filter = new PreFilterAuthorizationMethodBeforeAdvice();
		filter.before(authentication, methodAuthorizationContext);
		PreAuthorizeAuthorizationManager advice = new PreAuthorizeAuthorizationManager();
		AuthorizationDecision decision = advice.check(authentication, methodAuthorizationContext);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
		assertThat(list).hasSize(1);
		assertThat(list.get(0)).isEqualTo("john");
	}

	@Test
	public void findFilterTargetWhenNameNotProvidedAndSingleArgListThenFiltersListReturningGrantedDecision()
			throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");
		List<String> list = new ArrayList<>();
		list.add("john");
		list.add("bob");
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingListFilterTargetNotProvided", new Class[] { List.class }, new Object[] { list });
		MethodAuthorizationContext methodAuthorizationContext = new MethodAuthorizationContext(mockMethodInvocation,
				TestClass.class);
		PreFilterAuthorizationMethodBeforeAdvice filter = new PreFilterAuthorizationMethodBeforeAdvice();
		filter.before(authentication, methodAuthorizationContext);
		PreAuthorizeAuthorizationManager advice = new PreAuthorizeAuthorizationManager();
		AuthorizationDecision decision = advice.check(authentication, methodAuthorizationContext);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
		assertThat(list).hasSize(1);
		assertThat(list.get(0)).isEqualTo("john");
	}

	@Test
	public void findFilterTargetWhenNameNotProvidedAndSingleArgArrayThenException() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingArrayFilterTargetNotProvided", new Class[] { String[].class },
				new Object[] { new String[] {} });
		MethodAuthorizationContext methodAuthorizationContext = new MethodAuthorizationContext(mockMethodInvocation,
				TestClass.class);
		PreFilterAuthorizationMethodBeforeAdvice filter = new PreFilterAuthorizationMethodBeforeAdvice();
		assertThatIllegalArgumentException().isThrownBy(() -> filter.before(authentication, methodAuthorizationContext))
				.withMessage(
						"A PreFilter expression was set but the method argument type class [Ljava.lang.String; is not filterable");
	}

	@Test
	public void findFilterTargetWhenNameNotProvidedAndNotSingleArgThenException() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingTwoArgsFilterTargetNotProvided", new Class[] { String.class, List.class },
				new Object[] { "", new ArrayList<>() });
		MethodAuthorizationContext methodAuthorizationContext = new MethodAuthorizationContext(mockMethodInvocation,
				TestClass.class);
		PreFilterAuthorizationMethodBeforeAdvice filter = new PreFilterAuthorizationMethodBeforeAdvice();
		assertThatIllegalStateException().isThrownBy(() -> filter.before(authentication, methodAuthorizationContext))
				.withMessage("Unable to determine the method argument for filtering. Specify the filter target.");
	}

	@Test
	public void preAuthorizeWhenArgIsGrantThenGrantedDecision() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingString", new Class[] { String.class }, new Object[] { "grant" });
		MethodAuthorizationContext methodAuthorizationContext = new MethodAuthorizationContext(mockMethodInvocation,
				TestClass.class);
		PreAuthorizeAuthorizationManager advice = new PreAuthorizeAuthorizationManager();
		AuthorizationDecision decision = advice.check(authentication, methodAuthorizationContext);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void preAuthorizeWhenArgIsNotGrantThenDeniedDecision() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingString", new Class[] { String.class }, new Object[] { "deny" });
		MethodAuthorizationContext methodAuthorizationContext = new MethodAuthorizationContext(mockMethodInvocation,
				TestClass.class);
		PreAuthorizeAuthorizationManager advice = new PreAuthorizeAuthorizationManager();
		AuthorizationDecision decision = advice.check(authentication, methodAuthorizationContext);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void preFilterPreAuthorizeWhenListContainsGrantThenFiltersListReturningGrantedDecision() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");
		List<String> list = new ArrayList<>();
		list.add("grant");
		list.add("deny");
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingPreFilterPreAuthorizeList", new Class[] { List.class }, new Object[] { list });
		MethodAuthorizationContext methodAuthorizationContext = new MethodAuthorizationContext(mockMethodInvocation,
				TestClass.class);
		PreFilterAuthorizationMethodBeforeAdvice filter = new PreFilterAuthorizationMethodBeforeAdvice();
		filter.before(authentication, methodAuthorizationContext);
		PreAuthorizeAuthorizationManager advice = new PreAuthorizeAuthorizationManager();
		AuthorizationDecision decision = advice.check(authentication, methodAuthorizationContext);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
		assertThat(list).hasSize(1);
		assertThat(list.get(0)).isEqualTo("grant");
	}

	@Test
	public void preFilterPreAuthorizeWhenListNotContainsGrantThenFiltersListReturningDeniedDecision() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");
		List<String> list = new ArrayList<>();
		list.add("deny");
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingPreFilterPreAuthorizeList", new Class[] { List.class }, new Object[] { list });
		MethodAuthorizationContext methodAuthorizationContext = new MethodAuthorizationContext(mockMethodInvocation,
				TestClass.class);
		PreFilterAuthorizationMethodBeforeAdvice filter = new PreFilterAuthorizationMethodBeforeAdvice();
		filter.before(authentication, methodAuthorizationContext);
		PreAuthorizeAuthorizationManager advice = new PreAuthorizeAuthorizationManager();
		AuthorizationDecision decision = advice.check(authentication, methodAuthorizationContext);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
		assertThat(list).isEmpty();
	}

	public static class TestClass {

		@PreFilter(value = "filterObject == 'john'", filterTarget = "filterTargetNotMatch")
		public List<String> doSomethingListFilterTargetNotMatch(List<String> list) {
			return list;
		}

		@PreFilter(value = "filterObject == 'john'", filterTarget = "list")
		public List<String> doSomethingListFilterTargetMatch(List<String> list) {
			return list;
		}

		@PreFilter("filterObject == 'john'")
		public List<String> doSomethingListFilterTargetNotProvided(List<String> list) {
			return list;
		}

		@PreFilter("filterObject == 'john'")
		public String[] doSomethingArrayFilterTargetNotProvided(String[] array) {
			return array;
		}

		@PreFilter("filterObject == 'john'")
		public List<String> doSomethingTwoArgsFilterTargetNotProvided(String s, List<String> list) {
			return list;
		}

		@PreFilter("filterObject == 'john'")
		public String[] doSomethingArray(String[] array) {
			return array;
		}

		@PreAuthorize("#s == 'grant'")
		public String doSomethingString(String s) {
			return s;
		}

		@PreFilter("filterObject == 'grant'")
		@PreAuthorize("#list?.contains('grant')")
		public List<String> doSomethingPreFilterPreAuthorizeList(List<String> list) {
			return list;
		}

		public void doSomething() {

		}

	}

}
