# Investigating the Order of Spring Security Filters through Debugging
https://docs.spring.io/spring-security/reference/servlet/architecture.html

<img src="https://github.com/user-attachments/assets/40abb88c-738d-4348-ad2c-b2aa74b6b037" width="720" height="440">

예전 포스터에서 언급했다시피 Servlet Container는 DelegatingFilterProxy를 통해 필터 등록을 외부에 위임합니다. 
이를 통해 서블릿 필터와 스프링 필터가 등록되는 시간의 불일치를 해결할 수 있습니다.

이러한 아키텍쳐에 대한 장점 및 특징이 궁금하신 분은 이전의 게시물을 참고 하시고, 이번 포스팅의 주제는 디버깅을 통해 스프링 시큐리티 필터의 순서를 확인해 보는 것입니다.

## Define Custom Filter

```java
public class RequestVaildationFilter implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        var httpRequest = (HttpServletRequest)request;
        var httpResponse = (HttpServletResponse)response;

        String requestId = httpRequest.getHeader("Request-Id");

        if(requestId==null || requestId.isBlank()) {
            httpResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        chain.doFilter(request,response);

    }
}
```

## Defin SecurityFilterChain

```java
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.addFilterBefore(new RequestVaildationFilter(), BasicAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth.requestMatchers("/hello").authenticated()
                        .anyRequest().permitAll())
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }
```

RequsetVaildationFilter 가 BasicAuthenticaionFilter 바로 이전에 수행되게 했습니다.

## ApplicationFilterChain

```java
private void internalDoFilter(ServletRequest request, ServletResponse response)
            throws IOException, ServletException {

        // Call the next filter if there is one
        if (pos < n) {
            ApplicationFilterConfig filterConfig = filters[pos++];
            try {
                Filter filter = filterConfig.getFilter();

                if (request.isAsyncSupported() && !(filterConfig.getFilterDef().getAsyncSupportedBoolean())) {
                    request.setAttribute(Globals.ASYNC_SUPPORTED_ATTR, Boolean.FALSE);
                }
                if (Globals.IS_SECURITY_ENABLED) {
                    final ServletRequest req = request;
                    final ServletResponse res = response;
                    Principal principal = ((HttpServletRequest) req).getUserPrincipal();

                    Object[] args = new Object[] { req, res, this };
                    SecurityUtil.doAsPrivilege("doFilter", filter, classType, args, principal);
                } else {
                    filter.doFilter(request, response, this);
                }
            } catch (IOException | ServletException | RuntimeException e) {
                throw e;
            } catch (Throwable e) {
                e = ExceptionUtils.unwrapInvocationTargetException(e);
                ExceptionUtils.handleThrowable(e);
                throw new ServletException(sm.getString("filterChain.filter"), e);
            }
            return;
        }
```

위의 코드를 보면 pos를 증가시키면서 ServletFilter를 순서대로 실행하는 것을 확인할 수있습니다.

![스크린샷 2024-08-18 044851](https://github.com/user-attachments/assets/44604d5e-3a68-4280-bbb9-f478fc485e63)

servletFIlterChain에 5개의 필터가 등록되있는 것을 확인할 수 있습니다. 이미지를 자세하게 보시면 DelegatingFilterProxy가 FilterChain에서 4번째 순서로 존재한 다는 것을 알 수 있습니다.

<img src="https://github.com/user-attachments/assets/7196d476-8c3a-4df9-afa0-dce44c3085e6" width="600" height="370">

DelegatingFilterProxy 필터가 수행되기 전의 모습입니다.

## DelegatingFilterProxy
![스크린샷 2024-08-18 190121](https://github.com/user-attachments/assets/fd0a2217-e6ae-4450-bf98-0bdd834f9ff7)

```java
protected void invokeDelegate(
			Filter delegate, ServletRequest request, ServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		delegate.doFilter(request, response, filterChain);
	}
```
![스크린샷 2024-08-18 190437](https://github.com/user-attachments/assets/7c0305de-5f30-4422-8900-bb0c3d32beef)

DelegatingFilterProxy에서 필터 실행을 WebMvcSecurityConfiguration에 위임하고,

WebMvcSecurityConfiguration 은 CompositeFIlter에 위임합니다.

## CompositeFilter

<img src="https://github.com/user-attachments/assets/2d898b93-48df-4565-a06e-149649339a38" width="500" height="375">

```java
	private static class VirtualFilterChain implements FilterChain {

		private final FilterChain originalChain;

		private final List<? extends Filter> additionalFilters;

		private int currentPosition = 0;

		public VirtualFilterChain(FilterChain chain, List<? extends Filter> additionalFilters) {
			this.originalChain = chain;
			this.additionalFilters = additionalFilters;
		}

		@Override
		public void doFilter(final ServletRequest request, final ServletResponse response)
				throws IOException, ServletException {

			if (this.currentPosition == this.additionalFilters.size()) {
				this.originalChain.doFilter(request, response);
			}
			else {
				this.currentPosition++;
				Filter nextFilter = this.additionalFilters.get(this.currentPosition - 1);
				nextFilter.doFilter(request, response, this);
			}
		}
	}
```

CompositeFIlter는 VirtualFIlterChain이라는 내부 클래스를 통해서 필터를 실행합니다.

additionalFIlters에 HandlerMappingIntrospector와 FilterChainProxy 필터가 존재하고, int 변수인 curretPosition을 증가시키면서  순서대로 필터를 실행합니다. 

아래 그림을 통해 FilterChainProxy는 인덱스 1번에 존재하는 것을 알 수 있습니다.

![스크린샷 2024-08-18 201728](https://github.com/user-attachments/assets/b692142c-92fc-45a7-bff3-7fe3ec32002c)

## FilterChainProxy

```java
		@Override
		public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
			if (this.currentPosition == this.size) {
				this.originalChain.doFilter(request, response);
				return;
			}
			this.currentPosition++;
			Filter nextFilter = this.additionalFilters.get(this.currentPosition - 1);
			if (logger.isTraceEnabled()) {
				String name = nextFilter.getClass().getSimpleName();
				logger.trace(LogMessage.format("Invoking %s (%d/%d)", name, this.currentPosition, this.size));
			}
			nextFilter.doFilter(request, response, this);
		}
```

FilterChainProxy의 doFIlter메서드가 방금 전 보았던 VirtualFilterChain에서 filter을 호출하는 방식과 비슷하다는 것을 확인할 수 있습니다. </br></br>

여기서 주의깊게 봐야할 것은 if(this.currentPosition == this.size)를 통해 모든 필터를 실행한 후에는  originalFIlterChain(CompositeFilter)의 다음 필터가 실행되고 아닌 경우 내부의 다음 필터를 실행하는것을 알 수있습니다. </br></br>

즉, FIlterChainProxy에서 모든 필터를 실행했을 경우 CompositeFIlter로 이동하게 되고 , CompositeFIlter에서도 모든 필터를 실행했을 경우 ServletFIlterChain에서 다음 필터가 실행됩니다.</br></br>

전에 보았듯이 CompositeFIlter에는 HandlerMappingIntrospector 과 FilterChainProxy가 인덱스 0과 1로 존재합니다.  </br></br>
만약 FIlterChainPoxy에서 모든 필터가 수행되서 CompositeFIlter로 리턴되었다면 servletFilterChain에서 DelegatingFilterProxy는 4번째 순서이고, 5번재는 TomcatWebSocket 이므로 TomcatWebSocket이 실행될 차례라는 것을 알 수 있습니다.

![스크린샷 2024-08-18 204055](https://github.com/user-attachments/assets/7e496366-0d99-4646-a643-fe3f6599ee65)

그리고 FilterChainProxy의 특징으로는

```java
	private List<Filter> getFilters(HttpServletRequest request) {
		int count = 0;
		for (SecurityFilterChain chain : this.filterChains) {
			if (logger.isTraceEnabled()) {
				logger.trace(LogMessage.format("Trying to match request against %s (%d/%d)", chain, ++count,
						this.filterChains.size()));
			}
			if (chain.matches(request)) {
				return chain.getFilters();
			}
		}
		return null;
	}
```

filterchian이 해당 request에 대응되는지 확인하는 메서드인 chain.matches(request)가 존재한다는 것입니다. </br></br>

![스크린샷 2024-08-18 202236](https://github.com/user-attachments/assets/a6c50854-6827-41d6-b906-1575ed3dfb2f)

결론적으로  SecurityFIlterChain에서 currentPosition 변수를 증가시키면서 모든 내부 filter들을 실행할 것입니다. 

그리고 아까 우리가 추가했던 커스텀 필터가 인덱스 번호 7번째 에 존재한다는 것을 확인할 수있습니다. 그리고 이 커스텀 필터가 우리가 설정했던 대로 BasicAuthenticationFilter앞에 존재하는 것을 확인해 볼 수 있습니다.

디버깅을 가독성있게 포스팅하는것에 어려움을 느껴서 조금 아쉬운 마음이 들기는 합니다. 그래도 ServletFilterChain에서 필터 순서와 SecurityFIlterChain에서 필터순서를 알게 되었다면 그래도 얻은 것은 분명히 존재한다고 생각합니다.
