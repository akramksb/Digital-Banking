import { Component, OnDestroy, OnInit } from '@angular/core';
import { Subscription } from 'rxjs';
import { StorageService } from './services/storage.service';
import { EventBusService } from './_shared/event-bus.service';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent implements OnInit, OnDestroy {
  private roles: string[] = [];
  isLoggedIn = false;
  username?: string;
  eventBusSub?: Subscription;
  constructor(private storageService: StorageService, private eventBusService: EventBusService) { }
  ngOnInit(): void {
    this.isLoggedIn = !!this.storageService.getToken();
    if (this.isLoggedIn) {
      const user = this.storageService.getUser();
      this.roles = user.roles;
      this.username = user.username;
    }
    this.eventBusSub = this.eventBusService.on('logout', () => {
      this.logout();
    });
  }
  ngOnDestroy(): void {
    if (this.eventBusSub)
      this.eventBusSub.unsubscribe();
  }
  logout(): void {
    this.storageService.signOut();
    this.isLoggedIn = false;
    this.roles = [];
  }
}