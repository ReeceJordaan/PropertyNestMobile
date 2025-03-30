import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';

@Component({
  selector: 'app-tab3',
  templateUrl: 'tab3.page.html',
  styleUrls: ['tab3.page.scss'],
})
export class Tab3Page implements OnInit {
  userName!: string;

  constructor(private router: Router) {}

  ngOnInit() {
    this.userName = localStorage.getItem('name') || 'Guest';
  }

  logoutUser () {
    localStorage.removeItem("apikey");
    localStorage.removeItem("name");
    localStorage.removeItem("searchLocation");
    this.router.navigate(['/tabs/tab4']);
  }
}