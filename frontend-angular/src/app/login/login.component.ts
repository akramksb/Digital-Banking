import { Component, OnInit } from '@angular/core';
import {FormBuilder, FormGroup, Validators } from "@angular/forms";
import {Router} from "@angular/router";
import {AuthService} from "../services/auth-service";


@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent {
  loginFormGroup!:FormGroup;
  error!:string|null;

  constructor(private fb:FormBuilder,
              private authService: AuthService,
              private router: Router) {
    this.loginFormGroup = this.fb.group({
      username: ['',Validators.required],
      password: ['',Validators.required]
    });
  }

  login() {
    const val = this.loginFormGroup.value;

    if (val.username && val.password) {
      var v= this.authService.login(val.username, val.password)
        console.log(v)
        this.router.navigate(["/"])


    }
  }

}
