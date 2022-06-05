# Digital Banking

## Back End

### Entities
```Java
@Entity
@Inheritance(strategy = InheritanceType.SINGLE_TABLE)
@DiscriminatorColumn(name = "TYPE", length = 4)
@Data @NoArgsConstructor @AllArgsConstructor
public abstract class BankAccount {
    @Id
    private String id;
    private double balance;
    private Date createdAt;
    @Enumerated(EnumType.STRING)
    private AccountStatus status;
    @ManyToOne
    private Customer customer;
    @OneToMany(mappedBy = "bankAccount")
    private List<AccountOperation> accountOperations;
}
```

```Java
@Entity
@DiscriminatorValue("CA")
@Data @NoArgsConstructor @AllArgsConstructor
public class CurrentAccount extends BankAccount{
    private double overDraft;
}
```

```Java
@Entity
@DiscriminatorValue("SA")
@Data @NoArgsConstructor @AllArgsConstructor
public class SavingAccount extends BankAccount{
    private double interestRate;
}
```

```Java
@Entity
@Data @NoArgsConstructor @AllArgsConstructor
public class Customer {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;
    private String email;

    @OneToMany(mappedBy = "customer")
    private List<BankAccount> bankAccountList;
}
```

```Java
@Entity
@Data @NoArgsConstructor @AllArgsConstructor
public class AccountOperation {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private Date operationDate;
    private double amount;
    @Enumerated(EnumType.STRING)
    private OperationType type;
    private String description;
    @ManyToOne
    private BankAccount bankAccount;
}
```

### Web

#### BankAccountRestController

```Java
@RestController
@AllArgsConstructor
@CrossOrigin("*")
public class BankAccountRestController {
    private BankAccountService bankAccountService;

    @GetMapping("/accounts/{accountId}")
    public BankAccountDTO getBankAccount(String accountId) throws BankAccountNotFoundException {
        return bankAccountService.getBankAccount(accountId);
    }

    @GetMapping("/accounts")
    public List<BankAccountDTO> listAccount(){
        return bankAccountService.bankAccountList();
    }

    @GetMapping("/accounts/{accountId}/operations")
    public List<AccountOperationDTO> getHistory(@PathVariable String accountId){
        return bankAccountService.accountHistory(accountId);
    }

    @GetMapping("/accounts/{accountId}/pageOperations")
    public AccountHistoryDTO getHistory(
            @PathVariable String accountId,
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "5") int size) throws BankAccountNotFoundException {
        return bankAccountService.accountHistory(accountId, page, size);
    }

    @PostMapping("/accounts/debit")
    public DebitDTO debit(@RequestBody DebitDTO debitDTO) throws BankAccountNotFoundException, BalanceNotSufficientException {
        this.bankAccountService.debit(
                debitDTO.getAccountId(),
                debitDTO.getAmount(),
                debitDTO.getDescription()
        );
        return debitDTO;
    }

    @PostMapping("/accounts/credit")
    public CreditDTO debit(@RequestBody CreditDTO creditDTO) throws BankAccountNotFoundException {
        this.bankAccountService.credit(
                creditDTO.getAccountId(),
                creditDTO.getAmount(),
                creditDTO.getDescription()
        );
        return creditDTO;
    }

    @PostMapping("/accounts/transfer")
    public void debit(@RequestBody TransferRequestDTO transferRequestDTO) throws BankAccountNotFoundException, BalanceNotSufficientException {
        this.bankAccountService.transfer(
                transferRequestDTO.getAccountSource(),
                transferRequestDTO.getAccountDestination(),
                transferRequestDTO.getAmount()
        );
    }
}
```

#### CustomerRestController

```Java
@RestController
@AllArgsConstructor
@CrossOrigin("*")
public class CustomerRestController {
    private BankAccountService bankAccountService;

    @GetMapping("/customers")
    public List<CustomerDTO> customers(){
        return bankAccountService.listCustomers();
    }

    @GetMapping("/customers/search")
    public List<CustomerDTO> searchCustomers(@RequestParam(defaultValue = "") String keyword){
        return bankAccountService.searchCustomers("%"+keyword+"%");
    }

    @GetMapping("/customers/{id}")
    public CustomerDTO getCustomer(@PathVariable("id") Long customerTd) throws CustomerNotFoundException {
        return bankAccountService.getCustomer(customerTd);
    }

    @PostMapping("/customers")
    public CustomerDTO saveCustomer(@RequestBody CustomerDTO customerDTO){
        return bankAccountService.saveCustomer(customerDTO);
    }

    @PutMapping("/customers/{customerId}")
    public CustomerDTO updateCustomer(@PathVariable Long customerId, @RequestBody CustomerDTO customerDTO){
        customerDTO.setId(customerId);
        return bankAccountService.updateCustomer(customerDTO);
    }

    @DeleteMapping("/customers/{id}")
    public void deleteCustomer(@PathVariable Long id){
        bankAccountService.deleteCustomer(id);
    }
}
```

### Security

#### jwt filters
##### JwtAuthenticationFilter
```Java
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private AuthenticationManager authenticationManager;
    private AccountService accountServiceImpl;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager, AccountServiceImpl accountServiceImpl) {
        this.authenticationManager = authenticationManager;
        this.accountServiceImpl = accountServiceImpl;
    }

    @SneakyThrows
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String requestData = request.getReader().lines().collect(Collectors.joining());
        JSONObject json = new JSONObject(requestData);
        System.out.println(json);
        String username = json.getString("username");
        String password =json.getString("password");
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(username,password);
        return authenticationManager.authenticate(usernamePasswordAuthenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        User user = (User) authResult.getPrincipal();
        System.out.println("was success");
        Algorithm algorithm = Algorithm.HMAC256(JWTUtil.SECRET);
        String JwtAccessToken = JWT.create()
                        .withSubject(user.getUsername())
                        .withExpiresAt(new Date((System.currentTimeMillis()+ JWTUtil.EXPIRE_ACCESS_TOKEN)))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles",user.getAuthorities().stream().map(ga -> ga.getAuthority()).collect(Collectors.toList()))
                         .sign(algorithm);
        String JwtRefreshToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+JWTUtil.EXPIRE_REFRESH_TOKEN))
                .withIssuer(request.getRequestURL().toString())
                .sign(algorithm);
        Map<String,String> idToken = new HashMap<>();
        idToken.put("accessT",JwtAccessToken);
        idToken.put("refreshT",JwtRefreshToken);
        idToken.put("user",accountServiceImpl.loadUserByUsernameWithoutPass(user.getUsername()));
        response.setHeader("authorization",JwtAccessToken);
        response.setContentType("application/json");
        new ObjectMapper().writeValue(response.getOutputStream(),idToken);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {

    }
}
```

##### JwtAuthorizationFilter
```Java
public class JwtAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(request.getServletPath().equals("/auth/refreshToken") || request.getServletPath().equals("/login")){
            filterChain.doFilter(request,response);
        }
        else {
            String authorizationToken = request.getHeader(JWTUtil.AUTH_HEADER);
            if(authorizationToken!=null && authorizationToken.startsWith(JWTUtil.PREFIX)){
                try{
                    String jwt = authorizationToken.substring(JWTUtil.PREFIX.length());
                    Algorithm algorithm = Algorithm.HMAC256(JWTUtil.SECRET);
                    JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                    DecodedJWT decoded = jwtVerifier.verify(jwt);
                    String username = decoded.getSubject();
                    String[] roles = decoded.getClaim("roles").asArray(String.class);
                    Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
                    for(String r:roles){
                        grantedAuthorities.add(new SimpleGrantedAuthority(r));
                    }
                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken
                            = new UsernamePasswordAuthenticationToken(username,null,grantedAuthorities);
                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                    filterChain.doFilter(request,response);
                }catch (AuthenticationException | TokenExpiredException e){
                    response.resetBuffer ();
                    response.setStatus (HttpServletResponse.SC_UNAUTHORIZED);
                    response.flushBuffer ();
                    new RuntimeException(e);
                }
            }
            else{
                filterChain.doFilter(request,response);
            }

        }

    }
}
```

#### Security Config

```Java
@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    UserDetailsServiceImp userDetailsServiceImp;
    AccountServiceImpl accountService;
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsServiceImp);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.cors().configurationSource(request -> new CorsConfiguration().applyPermitDefaultValues());
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.headers().frameOptions().disable();
        http.authorizeRequests().antMatchers("/auth/refreshToken/**").permitAll();
        http.authorizeRequests().anyRequest().authenticated();
        http.addFilter(new JwtAuthenticationFilter(authenticationManagerBean(),accountService));
        http.addFilterBefore(new JwtAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
    }
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
```

#### Web
##### AccountRestController
```Java
@RestController
@CrossOrigin
@RequestMapping("/auth")
@AllArgsConstructor
public class AccountRestController {
    AccountService accountService;
    @PostAuthorize("hasAnyAuthority('USER')")
    @GetMapping("/users")
    List<AppUser> appUsers(){
        return accountService.listUsers();
    }
    @PostAuthorize("hasAnyAuthority('ADMIN')")
    @PostMapping("/users")
    AppUser saveUser(@RequestBody AppUser appUser){
        return accountService.addNewUser(appUser);
    }
    @PostAuthorize("hasAnyAuthority('ADMIN')")

    @PostMapping("/roles")
    AppRole saveRole(@RequestBody AppRole appRole){
        return accountService.addNewRole(appRole);
    }
    @PostAuthorize("hasAnyAuthority('ADMIN')")
    @PostMapping("/addRoleToUser")
    void addRoleToUser(@RequestBody RoleUserForm roleUserForm){
        accountService.addRoleToUser(roleUserForm.getUsername(),roleUserForm.getRoleName());
    }
    @PostAuthorize("hasAnyAuthority('USER')")
    @GetMapping("/profile")
    public AppUser profile(Principal principal){
        return accountService.loadUserByUsername(principal.getName());

    }
    @PostMapping("/refreshToken")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        System.out.println("**************************** refresh authentication request"+request.getHeader(JWTUtil.AUTH_HEADER));
        String authToken = request.getHeader(JWTUtil.AUTH_HEADER);
        if(authToken!=null && authToken.startsWith(JWTUtil.PREFIX)){
            try{
                String jwt = authToken.substring(JWTUtil.PREFIX.length());
                Algorithm algorithm = Algorithm.HMAC256(JWTUtil.SECRET);
                JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                DecodedJWT decoded = jwtVerifier.verify(jwt);
                String username = decoded.getSubject();
                AppUser appUser = accountService.loadUserByUsername(username);
                String JwtAccessToken = JWT.create()
                        .withSubject(appUser.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis()+JWTUtil.EXPIRE_ACCESS_TOKEN))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles",appUser.getAppRoles().stream().map(r -> r.getRoleName()).collect(Collectors.toList()))
                        .sign(algorithm);
                Map<String,String> idToken = new HashMap<>();
                idToken.put("accessT",JwtAccessToken);
                idToken.put("refreshT",jwt);
                response.setHeader("authorization",JwtAccessToken);
                response.setContentType("application/json");
                new ObjectMapper().writeValue(response.getOutputStream(),idToken);
                System.out.println(idToken);
                System.out.println(idToken);
                System.out.println(idToken);
            }catch (Exception e){
                System.out.println("error");
                System.out.println(e);
                throw e;
            }
        }
        else{
            new RuntimeException("Refresh Token required");
        }

    }
}
```

## Front End

### Models

```TS
export interface AccountDetails {
    accountId:            string;
    balance:              number;
    currentPage:          number;
    totalPages:           number;
    pageSize:             number;
    accountOperationDTOS: AccountOperation[];
}

export interface AccountOperation {
    id:            number;
    operationDate: Date;
    amount:        number;
    type:          string;
    description:   string;
}

export interface Customer{
    id : number;
    name : string;
    email : string;
}

export class UserModel {
  id :number
  username : string;
  roles : Array<string>;
  get roleT(): Array<string> {
    return this.roles;
  }
}

```

### Services

#### AuthService

```TS
export class AuthService {
  headers = new HttpHeaders().set('Content-Type', 'application/json');
  currentUser :any;

  constructor(private http: HttpClient, public router: Router,public storageService:StorageService) {}
  
  signUp(user: UserModel): Observable<any> {
    let api = `${environment.backendHost}/register-user`;
    return this.http.post(api, user).pipe(catchError(this.handleError));
  }

  login(username:string, password:string) {
    const body = {
      "username": username,
      "password":password
    };
    console.log(body)
    this.http
      .post<any>(`${environment.backendHost}/login`, body,{ context: new HttpContext().set(BYPASS_LOG, true) })
      .subscribe((res: any) => {
        if(res.accessT){
          console.log(res.accessT)
          var json = JSON.parse(res.user);
          console.log(json)
          this.currentUser = json;
          this.storageService.saveUser(json);
          this.storageService.saveToken(res.accessT)
          this.storageService.saveRefreshToken(res.refreshT);
          console.log(res.user)

        }else {
          this.storageService.saveUser(null);
        }
      });
    return this.storageService.getUser();
  }
  getToken() {
    return this.storageService.getToken();
  }
  get isLoggedIn(): boolean {
    let authToken = this.storageService.getToken();
    return authToken !== null ? true : false;
  }
  doLogout() {
    let removeUser = this.storageService.dologout();
    if (removeUser == null) {
      this.router.navigate(['login']);
    }
  }
  
  getUserProfile(id: any): Observable<any> {
    let api = `${environment.backendHost}/auth/profile/${id}`;
    return this.http.get(api, { headers: this.headers }).pipe(
      map((res) => {
        return res || {};
      }),
      catchError(this.handleError)
    );
  }

  refreshToken(token: string) {
    let heade =  {headers: new  HttpHeaders({ 'Authorization': 'Bearer ' + token})};
    
    return this.http.post(environment.backendHost + '/auth/refreshToken',{ headers: this.headers },heade);
  }
  getRole(){
    console.log(this.storageService.getUser().appRoles)
    return this.storageService.getUser().appRoles;
  }

  
  handleError(error: HttpErrorResponse) {
    let msg = '';
    if (error.error instanceof ErrorEvent) {
      
      msg = error.error.message;
    } else {
      msg = `Error Code: ${error.status}\nMessage: ${error.message}`;
    }
    return throwError(msg);
  }

}
```

#### AuthInterceptor

```TS
export class AuthInterceptor implements HttpInterceptor {
  private isRefreshing = false;
  private refreshTokenSubject: BehaviorSubject<any> = new BehaviorSubject<any>(null);
  constructor(private tokenService: StorageService, private authService: AuthService) { }
  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<Object>>  {
    if (req.context.get(BYPASS_LOG) === true || req.url.includes("/auth/refreshToken")){
      return next.handle(req);
    }
    let authReq = req;
    const token = this.tokenService.getToken();
    if (token != null) {
      authReq = this.addTokenHeader(req, token);
    }
    return next.handle(authReq).pipe(catchError(error => {
      if ( error.status === 401) {
        return this.handle401Error(authReq, next);
      }
      return throwError(error);
    }));
  }
  private handle401Error(request: HttpRequest<any>, next: HttpHandler) {
    if (!this.isRefreshing) {
      this.isRefreshing = true;
      this.refreshTokenSubject.next(null);
      const token = this.tokenService.getRefreshToken();
      if (token){
        return this.authService.refreshToken(token).pipe(
          switchMap((token: any) => {
            this.isRefreshing = false;
            this.tokenService.saveToken(token.accessT);
            this.refreshTokenSubject.next(token.accessT);
            return next.handle(this.addTokenHeader(request, token.accessT));
          }),
          catchError((err) => {
            this.isRefreshing = false;
            this.tokenService.signOut();
            return throwError(err);
          })
        );
      }

    }
    return this.refreshTokenSubject.pipe(
      filter(token => token !== null),
      take(1),
      switchMap((token) => next.handle(this.addTokenHeader(request, token)))
    );
  }
  private addTokenHeader(request: HttpRequest<any>, token: string) {
    return request.clone({ headers: request.headers.set(TOKEN_HEADER_KEY, 'Bearer ' + token) });
  }
}
export const authInterceptorProviders = [
  { provide: HTTP_INTERCEPTORS, useClass: AuthInterceptor, multi: true }
];

```

#### StorageService

```TS
export class StorageService {
  constructor() { }
  signOut(): void {
    localStorage.clear();
  }
  public saveToken(token: string): void {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.setItem(TOKEN_KEY, token);
    const user = this.getUser();
    if (user.id) {
      this.saveUser({ ...user, accessToken: token });
    }
  }
  public getToken(): string | null {
    return localStorage.getItem(TOKEN_KEY);
  }
  public saveRefreshToken(token: string): void {
    localStorage.removeItem(REFRESHTOKEN_KEY);
    localStorage.setItem(REFRESHTOKEN_KEY, token);
  }
  public getRefreshToken(): string | null {
    return localStorage.getItem(REFRESHTOKEN_KEY);
  }
  public saveUser(user: any): void {
    localStorage.removeItem(USER_KEY);
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  }
  public getUser(): any {
    const user = localStorage.getItem(USER_KEY);
    if (user) {
      return JSON.parse(user);
    }
    return {};
  }

  public dologout(): void {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(REFRESHTOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    return this.getUser();
  }
}

```





















