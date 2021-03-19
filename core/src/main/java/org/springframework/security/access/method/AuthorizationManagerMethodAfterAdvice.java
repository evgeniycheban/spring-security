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

import java.lang.annotation.Annotation;
import java.util.function.Supplier;

import org.springframework.aop.MethodMatcher;
import org.springframework.aop.support.annotation.AnnotationMethodMatcher;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;

public class AuthorizationManagerMethodAfterAdvice<T> implements AuthorizationMethodAfterAdvice<T> {
	private final MethodMatcher methodMatcher;
	private final AuthorizationManager<T> authorizationManager;

	public AuthorizationManagerMethodAfterAdvice(Class<? extends Annotation> annotationClass, AuthorizationManager<T> authorizationManager) {
		this(new AnnotationMethodMatcher(annotationClass, true), authorizationManager);
	}

	public AuthorizationManagerMethodAfterAdvice(MethodMatcher methodMatcher, AuthorizationManager<T> authorizationManager) {
		this.methodMatcher = methodMatcher;
		this.authorizationManager = authorizationManager;
	}

	@Override
	public Object after(Supplier<Authentication> authentication, T object, Object returnedObject) {
		this.authorizationManager.verify(authentication, object);
		return returnedObject;
	}

	@Override
	public MethodMatcher getMethodMatcher() {
		return this.methodMatcher;
	}
}
