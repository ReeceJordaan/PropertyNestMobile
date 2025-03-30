import { Component } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { FormControl } from '@angular/forms';
import { CurrencyFormatPipe } from './currency-format.pipe';
import { ToastController } from '@ionic/angular';

@Component({
  selector: 'app-tab2',
  templateUrl: 'tab2.page.html',
  styleUrls: ['tab2.page.scss'],
  providers: [CurrencyFormatPipe]
})
export class Tab2Page {

  isLoading: boolean = true;
  hasListings: boolean = false;
  hasNoListings: boolean = false;
  houseInfoJSON: any[] = [];
  searchControl: FormControl = new FormControl('');

  constructor(private http: HttpClient, private toastController: ToastController) {}

  ionViewWillEnter() {
    this.loadListings();
  }

  loadListings() {
    if (localStorage.getItem('apikey') == null) {
      this.hideAllContent();
    } else {
      const storedSearchLocation = localStorage.getItem('searchLocation');
      this.searchControl.setValue(storedSearchLocation);
      this.showLoading();
      this.fetchListings(storedSearchLocation);
    }
  }  

  fetchListings(searchLocation: string | null = null) {
    const text = {
      type: "GetAllListings",
      apikey: localStorage.getItem("apikey"),
      return: ["id", "title", "location", "price", "bedrooms", "bathrooms", "type", "images"],
      limit: 30,
      search: { location: searchLocation }
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

  searchListings() {
    const searchLocation = this.searchControl.value.trim() === '' ? null : this.searchControl.value;
    localStorage.setItem('searchLocation', searchLocation || '');
    this.showLoading();
    this.fetchListings(searchLocation);
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