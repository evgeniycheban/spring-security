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

import java.util.function.Supplier;

import org.springframework.aop.MethodMatcher;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;

public class AuthorizationManagerMethodBeforeAdvice<T> implements AuthorizationMethodBeforeAdvice<T> {
	private final MethodMatcher methodMatcher;
	private final AuthorizationManager<T> authorizationManager;

	public AuthorizationManagerMethodBeforeAdvice(MethodMatcher methodMatcher, AuthorizationManager<T> authorizationManager) {
		this.methodMatcher = methodMatcher;
		this.authorizationManager = authorizationManager;
	}

	@Override
	public void before(Supplier<Authentication> authentication, T object) {
		this.authorizationManager.verify(authentication, object);
	}

	@Override
	public MethodMatcher getMethodMatcher() {
		return this.methodMatcher;
	}
}
