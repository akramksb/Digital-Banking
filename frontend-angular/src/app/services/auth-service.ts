import { Injectable } from '@angular/core';

import { Observable, throwError } from 'rxjs';
import { catchError, map } from 'rxjs/operators';
import {StorageService} from "./storage.service";

import {
  HttpClient,
  HttpHeaders,
  HttpErrorResponse,
  HttpBackend, HttpContext
} from '@angular/common/http';
import { Router } from '@angular/router';
import {BYPASS_LOG} from "./authconfig.interceptor";
import { environment } from 'src/environments/environment.prod';
import { UserModel } from '../model/user.model';

@Injectable({
  providedIn: 'root',
})
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
