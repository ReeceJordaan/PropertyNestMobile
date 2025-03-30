import { Component, OnInit } from '@angular/core';
import { Router, NavigationEnd } from '@angular/router';

@Component({
  selector: 'app-tabs',
  templateUrl: 'tabs.page.html',
  styleUrls: ['tabs.page.scss']
})
export class TabsPage implements OnInit {

  userName: string = '';

  constructor(private router: Router) {
    this.router.events.subscribe(event => {
      if (event instanceof NavigationEnd) {
        if (event.urlAfterRedirects === '/tabs/tab4') {
          this.userName = localStorage.getItem('name') || 'Guest';
        }
      }
    });
  }

  ngOnInit() {
    this.setDefaultTab();
  }

  isLoggedIn(): boolean {
    return !!localStorage.getItem('apikey');
  }

  setDefaultTab() {
    if (this.isLoggedIn()) {
      this.router.navigate(['/tabs/tab1']);
    } else {
      this.router.navigate(['/tabs/tab4']);
    }
  }
}
