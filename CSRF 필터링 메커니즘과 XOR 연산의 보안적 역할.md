# CSRF 필터링 메커니즘과 XOR 연산의 보안적 역할
</br>

![스크린샷 2024-08-24 050516](https://github.com/user-attachments/assets/0ce69d1d-23c6-40ca-ae1c-752235ff8c73)

## Section 1
### RepositoryDeferredCsrfToken
```java
private void init() {
		if (this.csrfToken != null) {
			return;
		}

		this.csrfToken = this.csrfTokenRepository.loadToken(this.request);
		this.missingToken = (this.csrfToken == null);
		if (this.missingToken) {
			this.csrfToken = this.csrfTokenRepository.generateToken(this.request);
			this.csrfTokenRepository.saveToken(this.csrfToken, this.request, this.response);
		}
	}
```

csrfTokenRepository에서 httpServletRequest에 대응하는 토큰이 있는지 조회합니다.

존재하지 않으면 토큰을 생성 후 저장합니다.

일반적으로 csrfTokenRepository 구현체로 HttpSesstionCsrfTokenRepository가 사용됩니다. UUID가 토큰 값이며 이 토큰은 HttpSession에 저장되는 방식입니다.
</br>
이제 xor연산이 사용된 requesthandler를 분석해봅시다.

```java
private CsrfTokenRequestHandler requestHandler = new XorCsrfTokenRequestAttributeHandler();
```

### XorCsrfTokenRequestAttributeHandler

이 클래스는 CsrftokenRequestHandler 인터페이스의 구현체로, 각 요청에 대해 CsrfToken을 마스킹하고, 마스킹된 값을 raw token으로 해석하는 기능을 가집니다.

```java
private static String createXoredCsrfToken(SecureRandom secureRandom, String token) {
		byte[] tokenBytes = Utf8.encode(token);
		byte[] randomBytes = new byte[tokenBytes.length];
		secureRandom.nextBytes(randomBytes);

		byte[] xoredBytes = xorCsrf(randomBytes, tokenBytes);
		byte[] combinedBytes = new byte[tokenBytes.length + randomBytes.length];
		System.arraycopy(randomBytes, 0, combinedBytes, 0, randomBytes.length);
		System.arraycopy(xoredBytes, 0, combinedBytes, randomBytes.length, xoredBytes.length);

		return Base64.getUrlEncoder().encodeToString(combinedBytes);
	}
```
tokenBytes와 randomBytes를 xor 연산하여 xoredBytes를 생성한 후, 이를 randomBytes와 결합하여 인코딩을함으로써 마스킹된 값을 생성합니다. 
따라서 마스킹된 값은 tokenBytes의 사이즈의 2배입니다.

```java
private static String getTokenValue(String actualToken, String token) {
		byte[] actualBytes;
		try {
			actualBytes = Base64.getUrlDecoder().decode(actualToken);
		}
		catch (Exception ex) {
			return null;
		}

		byte[] tokenBytes = Utf8.encode(token);
		int tokenSize = tokenBytes.length;
		if (actualBytes.length != tokenSize * 2) {
			return null;
		}

		// extract token and random bytes
		byte[] xoredCsrf = new byte[tokenSize];
		byte[] randomBytes = new byte[tokenSize];

		System.arraycopy(actualBytes, 0, randomBytes, 0, tokenSize);
		System.arraycopy(actualBytes, tokenSize, xoredCsrf, 0, tokenSize);

		byte[] csrfBytes = xorCsrf(randomBytes, xoredCsrf);
		return Utf8.decode(csrfBytes);
	}
```
클라이언트가 헤더나 파라미터를 통해 전송한 Csrftoken값을 해석하는 함수입니다.

![IMG_0275](https://github.com/user-attachments/assets/ac41cb63-ef20-4bb9-a405-ed790bf17ef4)

같은 피연산자에 대해 XOR 연산을 하면 0이 된다는 성질을 활용하여, 동일한 raw 토큰 값이지만 매 요청마다 서로 다른 마스킹된 값을 생성할 수 있었습니다. 
이어서 클라이언트가 파라미터나 헤더를 통해 마스킹된 토큰 값을 전달하면, 
XOR 연산을 다시 한 번 수행하여 간단히 raw 토큰 값을 복원할 수 있었습니다.

### Define customCsrfTokenLoggerFilter

```java
public class CsrfTokenLogger implements Filter {

    private Logger logger = LoggerFactory.getLogger(CsrfTokenLogger.class.getName());

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        Object o = request.getAttribute("_csrf");
        CsrfToken token = (CsrfToken)o;

        logger.info("CSRF token : {}",token.getToken());

        chain.doFilter(request,response);

    }
}
```
토큰 값을 확인하기 위해 커스텀 필터를 정의했습니다. 사용자가 요청을 할때마다 새로운 마스킹된 토큰 값이 생성되는 것을 확인할 수 있습니다.
이는 난수와 토큰 값을 XOR 연산하여 매번 다른 값을 생성하는 방십입니다. 
즉, 세션에 바인딩된 raw Token 값은 동일하지만, 각 요청마다 다른 마스킹된 토큰값이 생성되어 보안이 강화됩니다. 
아래의 그림에서 모든 마스킹된 토큰값은 동일한 raw 토큰값을 가리키고 있습니다.
![스크린샷 2024-08-24 192737](https://github.com/user-attachments/assets/6c6d2941-14ba-4e4d-9779-0168cb4c95fe)
![스크린샷 2024-08-24 192250](https://github.com/user-attachments/assets/e800d4a9-9933-4f7b-8d8a-7bfab0bba16d)

상태코드 200번대로 post 요청이 잘 작동하는 것을 확인할 수 있습니다.

## Section 2

```java
private static final class DefaultRequiresCsrfMatcher implements RequestMatcher {

		private final HashSet<String> allowedMethods = new HashSet<>(Arrays.asList("GET", "HEAD", "TRACE", "OPTIONS"));

		@Override
		public boolean matches(HttpServletRequest request) {
			return !this.allowedMethods.contains(request.getMethod());
		}

		@Override
		public String toString() {
			return "CsrfNotRequired " + this.allowedMethods;
		}

	}
```
get,head,trace,options 메서드에서는 csrf 공격이 발생하지 않기 때문에  위의 메소드들은 csrfFilter가 적용될 필요가 없습니다. 
따라서 위의 메서드일 경우에는 CsrfFilter를 수행하지 않고 filterChain에서 다음의 필터를 수행합니다.

## Section 3

scrfToken은 rawToken이며 actualToken은 클라이언트가 헤더나 파라미터를 통해 서버로 전송한 토큰입니다.
actualToken은 마스킹되어있기 때문에 xor연산을 다시한번 적용합니다.

## Section 4
사용자가 전송한 토큰과 실제 토큰을 비교하는 로직입니다. 만약 두 토큰 값이 같지 않다면 InvalidCsrfTokenException 예외가 발생하고, 
실제 토큰이 레포지토리에 존재하지 않는다면 MissingCsrfTokenException 예외가 발생합니다.

## Section 5
Csrf filter가 자신의 역할을 모두 수행했으므로 필터체인에서 다음의 필터를 실행합니다.

</br>
Spring Security in Action 교재를 통해 Csrf Token 로그를 출력하는 예제를 실습해보았습니다. 
매 요청마다 서로다른 문자열이 출력되었습니다. </br>
스프링 시큐리티에서 일반적인 Csrf 토큰 레포지토리 구현은 세션에 종속적인데  매번 다른 문자열이 출력되어서, 이전의 문자열은 토큰의 역할을 하는 지 궁금증이 생겼습니다.

api요청을 통해 확인해 본 결과 같은 세션에서 보낸 요청이라면 모두 유효한 토큰으로서 역할을 하는것이였습니다. 
이에 따라 하나의 세션에 여러개의 토큰값이 할당되는 것인지도  궁금했습니다. 그래서 CsrfFilter 코드를 분석해 보는 계기가 되었습니다.

토큰값과 난수에 xor 연산을 하면 동일한 raw Token에서 여러개의 마스킹된 값을 생성할 수 있고, 
마스킹된 값을 해석할때에는 단순히 xor연산을 다시 적용함으로써 본래의 토큰값을 얻을 수 있다는 것이 인상적이였습니다.
