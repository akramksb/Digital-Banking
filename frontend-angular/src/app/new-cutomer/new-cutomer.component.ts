import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { CustomerService } from '../services/customer.service';

@Component({
  selector: 'app-new-cutomer',
  templateUrl: './new-cutomer.component.html',
  styleUrls: ['./new-cutomer.component.css']
})
export class NewCustomerComponent implements OnInit {
  newCustomerFormGroup! : FormGroup;
  constructor(private fb : FormBuilder,
    private customerService : CustomerService,
    private router : Router) { }

  ngOnInit(): void {
    this.newCustomerFormGroup = this.fb.group({
      name : this.fb.control(null, [Validators.required]),
      email : this.fb.control(null, [Validators.required, Validators.email])
    })
  }

  handleSaveCustomer(){
    let customer = this.newCustomerFormGroup.value;
    this.customerService.saveCustomer(customer).subscribe({
      next : data => {
        alert("customer saved successfully");
        // this.newCustomerFormGroup.reset();
        this.router.navigateByUrl("/customers");
      },
      error : err => console.log(err)
    });
  }

}
