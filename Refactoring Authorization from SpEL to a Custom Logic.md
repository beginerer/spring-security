# Refactoring Authorization from SpEL to a Custom Logic
https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html#authorization-expressions

시작하기에 앞서 간략하게 스프링 시큐리티의 Servlet Application의 아키텍처에 간략하게 설명하겠습니다.

 스프링 시큐리티의 서블릿은 서블릿 필더구조에 기반합니다. </br>
 문제는 서블릿 필터와 스프링 필더가 등록되는 시간의 차이가  존재합니다.</br> 
 서블릿 컨테이너가 작동하면서 필터를 초기화 하는 과정을 거치는데 이때 Spring-defined Beans의 존재를 알 지 못하기 때문입니다.

<img src="https://github.com/user-attachments/assets/bc5d4f01-2d87-4f13-bb70-2efe687420ca" width="700" height="470"/>
</br>
이를 해결해주는 것이 DelegatingFilterProxy입니다.</br></br>
DelegatingFIlterProxy는 서블릿 필터 중 하나로 필터 등록을 외부에 위임을 하며 서블릿 컨테이너는 외부의 어떤 필터가 등록될지 모릅니다.</br></br>

DelegatingFilterProxy는 Laze하게 Filter을 등록하고, 필터를 등록하는과정을 Spring에 위임하기 때문에 서블릿 컨테이너와 Spring의 간극을 매꿔주는 역할을 합니다.</br>

그림에서 보시는 FilterChainProxy가 @Bean으로된 Spring filter이고 이곳에 여러 개의 SecurityFilterChain 이 등록됩니다. </br>

SecurityFilterChain또한 @bean이고 차이점은 DelegatingFIlterProxy에 저장되는것이아니라 FilterChainProxy에 저장됩니다.

이렇게 하는것의 장점이 많이 존재하는데 간단하게 설명하자면 디버깅하는데 좋고, 
기존 서블릿이 오직 URL 매핑 기반인 것과 달리 SecurityFilterProxy의 경우 RequestMatcher 인터페이스를 사용하여 HttpServletRequest의 다양한 속성을 기반으로 호출여부을 결정할 수 있습니다.
</br>
## Understanding How Request Authorization Components Work
<img src="https://github.com/user-attachments/assets/14332e7b-97e5-4aa0-8fd5-bccdc06b8468" width="600" height="360"/>

1. First, the `AuthorizationFilter` constructs a `Supplier` that retrieves an [Authentication](https://docs.spring.io/spring-security/reference/servlet/authentication/architecture.html#servlet-authentication-authentication) from the [SecurityContextHolder](https://docs.spring.io/spring-security/reference/servlet/authentication/architecture.html#servlet-authentication-securitycontextholder).
2. Second, it passes the **`Supplier<Authentication>`** and the **`HttpServletRequest`** to the [`AuthorizationManager`](https://docs.spring.io/spring-security/reference/servlet/architecture.html#authz-authorization-manager). The `AuthorizationManager` matches the request to the patterns in `authorizeHttpRequests`, and runs the corresponding rule.
3.  If authorization is denied, [an `AuthorizationDeniedEvent` is published](https://docs.spring.io/spring-security/reference/servlet/authorization/events.html), and an `AccessDeniedException` is thrown. In this case the [`ExceptionTranslationFilter`](https://docs.spring.io/spring-security/reference/servlet/architecture.html#servlet-exceptiontranslationfilter) handles the `AccessDeniedException`.
4. If access is granted, [an `AuthorizationGrantedEvent` is published](https://docs.spring.io/spring-security/reference/servlet/authorization/events.html) and `AuthorizationFilter` continues with the [FilterChain](https://docs.spring.io/spring-security/reference/servlet/architecture.html#servlet-filters-review) which allows the application to process normally.
</br>

## RequestMatcherDelegatingAuthorizaionManager

``` java
@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication, HttpServletRequest request) {
		if (this.logger.isTraceEnabled()) {
			this.logger.trace(LogMessage.format("Authorizing %s", requestLine(request)));
		}
		for (RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> mapping : this.mappings) {

			RequestMatcher matcher = mapping.getRequestMatcher();
			MatchResult matchResult = matcher.matcher(request);
			if (matchResult.isMatch()) {
				AuthorizationManager<RequestAuthorizationContext> manager = mapping.getEntry();
				if (this.logger.isTraceEnabled()) {
					this.logger.trace(
							LogMessage.format("Checking authorization on %s using %s", requestLine(request), manager));
				}
				return manager.check(authentication,
						new RequestAuthorizationContext(request, matchResult.getVariables()));
			}
		}
		if (this.logger.isTraceEnabled()) {
			this.logger.trace(LogMessage.of(() -> "Denying request since did not find matching RequestMatcher"));
		}
		return DENY;
	}
```

매개변수로 supplier<Authentication> 과 httpServletRequest 가 존재하는 것을 확인해 볼 수 있습니다.

## Authorizing Requests

Once a request is matched, you can authorize it in several ways [already seen](https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html#match-requests) like `permitAll`, `denyAll`, and `hasAuthority`.

• `hasAuthority` - The request requires that the `Authentication` have [a `GrantedAuthority`](https://docs.spring.io/spring-security/reference/servlet/authorization/architecture.html#authz-authorities) that matches the given value
• `hasAnyAuthority` - The request requires that the `Authentication` have a `GrantedAuthority` that matches any of the given values

문제는 복잡한 권한로직이 필요할때 발생합니다.

예를 들어 어떤 엔드포인트에 접근하기 위해서는 ‘READ’권한이 존재하면서 ‘DELETE’권한이 존재하면 안되는 경우에 이를 기존의 메서드만으로는 해결하기에는 어렵습니다.
그러나 이를 해결해주는 것이 SpEL이고, SpEL를 통한 권한 인증 매니저가 이미 스프링에 구현되어 있습니다.

## Define UserDetails

``` java
@Bean
    public UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager userDetailService = new InMemoryUserDetailsManager();

        UserDetails user = User.withUsername("alex")
                .password("12345")
                .authorities("READ")
                .build();

        UserDetails user2 = User.withUsername("jane")
                .password("12345")
                .authorities("READ","WRITE","DELETE")
                .build();

        userDetailService.createUser(user);
        userDetailService.createUser(user2);
        return userDetailService;
    }
```

READ’권한을 가진 alex와 ‘READ, WRITE, DELETE’권한을 가진 jane을 생성했습니다.

## Using SpEL Logic

``` java
@Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        String expression = "hasAuthority('READ') && !hasAuthority('DELETE')";
        WebExpressionAuthorizationManager manager = new WebExpressionAuthorizationManager(expression);


        http.authorizeHttpRequests(auth -> auth.anyRequest().access(manager))
                .httpBasic(Customizer.withDefaults());

        return http.build();
    }
```
<img src="https://github.com/user-attachments/assets/7e3a879f-0417-4d3d-b4b4-92567857db9c" width="744" height="458"/>
<img src="https://github.com/user-attachments/assets/19b7c3f4-be2d-4d1c-a471-a73a236838cc" width="744" height="458"/>

‘READ’권한을 가지고 있는 alex는 엔드포인트에 접근가능하고, ‘READ’권한을 가지고 있지만 ‘DELETE’권한을 가지고 있는 jane은 엔드포인트에 접근불가능한것을 위의 그림을 통해 확인해 볼 수 있습니다.

## Using customLogic
```java
@Bean
    public SecurityFilterChain CustomFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth.anyRequest().access(customAuthorize))
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }
```
```java
@Component
public class CustomAuthorize implements AuthorizationManager<RequestAuthorizationContext> {
    // 사용자의 권한을 확인하는 메서드

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext request) {
        Collection<? extends GrantedAuthority> authorities = authentication.get().getAuthorities();

        List<Predicate<Authentication>> conditions = List.of(
                auth -> authorities.stream().anyMatch(authority -> authority.getAuthority().equals("READ")),
                auth -> authorities.stream().noneMatch(authority -> authority.getAuthority().equals("DELETE"))
        );
        boolean granted = conditions.stream().allMatch(condition-> condition.test(authentication.get()));
        return new AuthorizationDecision(granted);
    }
}
```
<img src="https://github.com/user-attachments/assets/6ca3480a-86fb-4495-964c-22144557b261" width="744" height="458"/>
<img src="https://github.com/user-attachments/assets/31cec527-480b-4087-a539-0b508253a913" width="744" height="458"/>

정상작동하는 것을 확인해 볼 수 있습니다.
SpEL 방식을 리팩토링해보면서 Spring security의 아키텍쳐에 대한 이해가 전보다 증가하게 된 계기가 되었습니다.
