import { Injectable } from '@angular/core';
const TOKEN_KEY = 'accessT';
const REFRESHTOKEN_KEY = 'refreshT';
const USER_KEY = 'user';
@Injectable({
  providedIn: 'root'
})
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
