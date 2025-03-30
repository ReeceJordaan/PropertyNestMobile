import { Component } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { CurrencyFormatPipe } from './currency-format.pipe';
import { ToastController } from '@ionic/angular';

@Component({
  selector: 'app-tab1',
  templateUrl: 'tab1.page.html',
  styleUrls: ['tab1.page.scss'],
  providers: [CurrencyFormatPipe]
})
export class Tab1Page {

  isLoading: boolean = true;
  hasListings: boolean = false;
  hasNoListings: boolean = false;
  houseInfoJSON: any[] = [];

  constructor(private http: HttpClient, private toastController: ToastController) {}

  ionViewWillEnter() {
    this.loadListings();
  }

  loadListings() {
    if (localStorage.getItem('apikey') == null) {
      this.hideAllContent();
    } else {
      this.showLoading();
      this.fetchListings();
    }
  }

  fetchListings() {
    const text = {
      type: "GetAllListings",
      apikey: localStorage.getItem("apikey"),
      return: ["id", "title", "location", "price", "bedrooms", "bathrooms", "type", "images"],
      limit: 30
    };

    this.http.post<any>("https://wheatley.cs.up.ac.za/u23547104/api.php", text, {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Basic ${btoa("u23547104:6F6FdO7ebFHiyZ00")}`
      }
    }).subscribe(
      response => {
        this.houseInfoJSON = response.data;
        this.populateListings();
        this.hideLoading();
      },
      error => {
        console.error('Error fetching listings:', error);
        this.createToast('Error fetching listings.');
        this.hideLoading();
      }
    );
  }

  populateListings() {
    if (this.houseInfoJSON.length === 0) {
      this.hideAllContent();
    } else {
      this.hasListings = true;
    }
  }

  private hideAllContent() {
    this.isLoading = false;
    this.hasListings = false;
    this.hasNoListings = true;
  }

  private showLoading() {
    this.isLoading = true;
    this.hasListings = false;
    this.hasNoListings = false;
  }

  private hideLoading() {
    this.isLoading = false;
    this.hasListings = true;
    this.hasNoListings = false;
  }

  async createToast(message: string) {
    const toast = await this.toastController.create({
      message: message,
      duration: 2000
    });
    
    toast.present();
  }

  handleRefresh(event: any) {
    this.loadListings();
    event.target.complete();
    this.createToast('Listings refreshed successfully!');
  }
}