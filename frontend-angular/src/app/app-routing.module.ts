import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import {CustomersComponent} from "./customers/customers.component";
import {AccountsComponent} from "./accounts/accounts.component";
import { NewCustomerComponent } from './new-cutomer/new-cutomer.component';
import { CustomerAccountsComponent } from './customer-accounts/customer-accounts.component';
import { AuthGuard } from './auth.guard';
import { LoginComponent } from './login/login.component';

const routes: Routes = [
  { path:"customers", component: CustomersComponent, canActivate: [AuthGuard],
  data: {
    role: 'ADMIN'
  }},
  {path : "accounts", component : AccountsComponent,canActivate: [AuthGuard],
    data: {
      role: 'ADMIN'
    }},
  { path :"new-customer", component : NewCustomerComponent,canActivate: [AuthGuard],
    data: {
      role: 'ADMIN'
    }},
    { path :"customer-accounts/:id", component : CustomerAccountsComponent,canActivate: [AuthGuard],
    data: {
      role: 'ADMIN'
    }},
    {path : "login", component : LoginComponent}
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
