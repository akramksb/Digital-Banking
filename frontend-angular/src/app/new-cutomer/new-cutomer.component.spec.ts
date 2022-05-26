import { ComponentFixture, TestBed } from '@angular/core/testing';

import { NewCutomerComponent } from './new-cutomer.component';

describe('NewCutomerComponent', () => {
  let component: NewCutomerComponent;
  let fixture: ComponentFixture<NewCutomerComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ NewCutomerComponent ]
    })
    .compileComponents();
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(NewCutomerComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
